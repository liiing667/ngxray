#!/usr/bin/env python3
"""
Extract raw nginx config blocks from wrapper formats (shell scripts, Jinja2
templates, ERB, Puppet manifests, Kubernetes YAML, Markdown, etc.) and write
clean .conf files into a processed/ output directory.

Files that are already plain nginx configs are copied through with only
light normalization (BOM strip, trailing whitespace).

Usage:
    python3 corpus_tools/extract_nginx_configs.py [--input-dir corpus_out/nginx/raw] [--output-dir corpus_out/nginx/extracted]
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path


# ── Detection ───────────────────────────────────────────────────────────────

def classify(content, filename):
    """Return a format tag for the file content."""
    s = content.strip()
    lower_name = filename.lower()
    if lower_name.startswith("dockerfile") or re.match(r"(?i)^FROM\s+", s):
        return "dockerfile"
    is_yaml_structure = (
        s.startswith("apiVersion") or
        (s.startswith("---") and "kind:" in content[:500]) or
        (s.startswith("#") and re.search(r"^apiVersion:", content, re.MULTILINE))
    )
    if is_yaml_structure:
        if "{{" in content or "{%" in content:
            return "k8s_yaml_jinja"
        return "k8s_yaml"
    if "{{" in content or "{%" in content:
        return "jinja"
    if "<%" in content:
        return "erb"
    if s.startswith("#!"):
        if "<<" in content or "cat >" in content or "tee " in content:
            return "shell_heredoc"
        return "shell_script"
    if re.match(r"^(class|define)\s", s):
        return "puppet"
    if filename.endswith(".pp"):
        return "puppet"
    if "```" in content and not re.match(r"^\s*(worker_processes|events|http|server|upstream|map|geo|limit_)", s):
        return "markdown"
    return "raw"


# ── Extractors ──────────────────────────────────────────────────────────────

def strip_jinja(content):
    """
    Replace Jinja2 constructs with plausible nginx-safe placeholders so the
    result is closer to valid nginx syntax.

    - {{ var }}          → __var__
    - {{ var | filter }} → __var__
    - {% if ... %}       → # jinja: if ...
    - {% else %}         → # jinja: else
    - {% endif %}        → # jinja: endif
    - {% for ... %}      → # jinja: for ...
    - {% endfor %}       → # jinja: endfor
    - {% block ... %}    → (dropped)
    - {# comment #}     → (dropped)
    """
    # Drop Jinja comments
    content = re.sub(r"\{#.*?#\}", "", content, flags=re.DOTALL)
    # Replace block tags with nginx comments
    def replace_tag(m):
        tag = m.group(1).strip()
        kw = tag.split()[0] if tag.split() else ""
        if kw in ("block", "endblock", "macro", "endmacro", "call", "endcall",
                   "raw", "endraw", "set"):
            return ""
        return f"# jinja: {tag}"
    content = re.sub(r"\{%[-+]?\s*(.*?)\s*[-+]?%\}", replace_tag, content, flags=re.DOTALL)
    # Replace expressions with placeholder identifiers
    def replace_expr(m):
        expr = m.group(1).strip()
        name = re.split(r"[|\s()\[\]{}.,+\-*/]", expr)[0].strip()
        name = re.sub(r"[^a-zA-Z0-9_]", "", name) or "VAR"
        return f"__{name}__"
    content = re.sub(r"\{\{\s*(.*?)\s*\}\}", replace_expr, content, flags=re.DOTALL)
    return content


def strip_erb(content):
    """Replace ERB tags with placeholders."""
    content = re.sub(r"<%#.*?%>", "", content, flags=re.DOTALL)
    def replace_erb_expr(m):
        expr = m.group(1).strip()
        name = re.split(r"[.\s()\[\]@,+\-*/]", expr)[0].strip()
        name = re.sub(r"[^a-zA-Z0-9_]", "", name) or "VAR"
        return f"__{name}__"
    content = re.sub(r"<%=\s*(.*?)\s*%>", replace_erb_expr, content, flags=re.DOTALL)
    content = re.sub(r"<%-?\s*(.*?)\s*-?%>", lambda m: f"# erb: {m.group(1).strip()}", content, flags=re.DOTALL)
    return content


def extract_heredoc(content):
    """
    Pull nginx config blocks out of shell heredoc constructs.

    Handles patterns like:
        cat > /path/to/nginx.conf <<EOF
        cat > /path/to/nginx.conf << 'EOF'
        cat > /path/to/nginx.conf <<- "EOF"
        tee /path/to/nginx.conf <<EOF
        tee /path/to/nginx.conf > /dev/null << EOF
    """
    configs = []
    # Match heredoc start: cat/tee/RUN/COPY/ADD ... <<[-]? ['"]?DELIM['"]?
    pattern = re.compile(
        r"(?:cat|tee|RUN|COPY|ADD)\s+.*?<<-?\s*['\"]?(\w+)['\"]?(?:\s+[^\n]*)?\s*\n",
        re.MULTILINE | re.IGNORECASE,
    )
    for m in pattern.finditer(content):
        delim = m.group(1)
        start = m.end()
        # Find the closing delimiter on its own line
        end_pattern = re.compile(r"^\s*" + re.escape(delim) + r"\s*$", re.MULTILINE)
        end_match = end_pattern.search(content, start)
        if end_match:
            block = content[start:end_match.start()]
            if looks_like_nginx(block):
                # Strip leading tabs (heredoc <<- strips tabs)
                block = re.sub(r"^\t+", "", block, flags=re.MULTILINE)
                configs.append(block)

    # Also try to find inline nginx blocks in shell scripts that use echo/printf
    # to build configs piecemeal — these are too fragmented to extract reliably,
    # so we skip them.

    return configs


def extract_from_shell(content):
    """
    Extract nginx configs from shell scripts. Tries heredocs first, then
    falls back to looking for bare nginx blocks between shell constructs.
    """
    heredocs = extract_heredoc(content)
    if heredocs:
        return heredocs

    # Some shell scripts contain a full nginx config after shell variable setup.
    # Try to find the first line that looks like an nginx directive and take
    # everything from there.
    lines = content.split("\n")
    start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"^(worker_processes|events\s*\{|http\s*\{|server\s*\{|upstream\s+|map\s+|geo\s+|limit_)", stripped):
            start = i
            break
    if start is not None:
        block = "\n".join(lines[start:])
        if looks_like_nginx(block):
            return [block]

    return []


def extract_from_puppet(content):
    """
    Extract nginx config snippets embedded in Puppet manifests.
    Look for content => '...' or template() references with inline heredocs.
    """
    configs = []
    # Puppet heredoc: @("END"/L)  or  @(END)
    for m in re.finditer(r"@\(\s*['\"]?(\w+)['\"]?\s*(?:/\w+)?\s*\)\s*\n", content):
        delim = m.group(1)
        start = m.end()
        end_pat = re.compile(r"^\s*\|\s*" + re.escape(delim) + r"\s*$|^\s*" + re.escape(delim) + r"\s*$", re.MULTILINE)
        end_m = end_pat.search(content, start)
        if end_m:
            block = content[start:end_m.start()]
            block = re.sub(r"^\s*\|", "", block, flags=re.MULTILINE)
            if looks_like_nginx(block):
                configs.append(block)

    # content => "..." (double-quoted, may span multiple lines with backslash)
    for m in re.finditer(r'content\s*=>\s*"((?:[^"\\]|\\.)*)"', content, re.DOTALL):
        block = m.group(1).replace("\\n", "\n").replace('\\"', '"').replace("\\$", "$")
        if looks_like_nginx(block):
            configs.append(block)

    # content => '...' (single-quoted)
    for m in re.finditer(r"content\s*=>\s*'((?:[^'\\]|\\.)*)'", content, re.DOTALL):
        block = m.group(1)
        if looks_like_nginx(block):
            configs.append(block)

    return configs


def extract_from_yaml(content):
    """
    Extract nginx config from Kubernetes ConfigMap data fields or
    similar YAML structures where config is embedded as a string value.
    """
    configs = []
    # Match YAML block scalars: key: |  or key: |-  followed by indented lines
    # Common pattern: data:\n  nginx.conf: |\n    server { ...
    for m in re.finditer(r"^\s*[\w.\-]+\.conf\s*:\s*\|[-+]?\s*\n((?:[ \t]+\S.*\n?)+)", content, re.MULTILINE):
        block = m.group(1)
        # Dedent
        indent = len(re.match(r"^([ \t]*)", block).group(1))
        if indent > 0:
            block = re.sub(r"^" + " " * indent, "", block, flags=re.MULTILINE)
        if looks_like_nginx(block):
            configs.append(block)

    # Also try generic block scalars after "data:" sections
    for m in re.finditer(r"^\s*(?:default\.conf|nginx\.conf|conf|config)\s*:\s*\|[-+]?\s*\n((?:[ \t]+\S.*\n?)+)", content, re.MULTILINE):
        block = m.group(1)
        indent = len(re.match(r"^([ \t]*)", block).group(1))
        if indent > 0:
            block = re.sub(r"^" + " " * indent, "", block, flags=re.MULTILINE)
        if looks_like_nginx(block) and block not in configs:
            configs.append(block)

    return configs


def extract_from_markdown(content):
    """
    Extract nginx configs from Markdown fenced code blocks.
    """
    configs = []
    for m in re.finditer(r"```(?:nginx|conf|bash|sh|text)?\s*\n(.*?)```", content, re.DOTALL):
        block = m.group(1)
        if looks_like_nginx(block):
            configs.append(block)
    return configs


def normalize_raw(content):
    """Light normalization for already-raw configs."""
    # Strip BOM
    if content.startswith("﻿"):
        content = content[1:]
    # Normalize line endings
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    # Strip trailing whitespace per line
    content = re.sub(r"[ \t]+$", "", content, flags=re.MULTILINE)
    # Strip trailing newlines
    content = content.rstrip("\n") + "\n"
    return content


# ── Validation ──────────────────────────────────────────────────────────────

NGINX_INDICATORS = [
    "server {", "location ", "listen ", "server_name ",
    "proxy_pass ", "worker_processes", "http {", "upstream ",
    "fastcgi_pass", "uwsgi_pass", "root ", "index ",
    "error_page ", "access_log ", "include ", "ssl_certificate",
    "proxy_set_header", "add_header ", "try_files ",
    "error_log ", "events {", "map ", "geo ",
    "limit_req", "rewrite ", "return ",
]


def looks_like_nginx(content):
    if not content or len(content.strip()) < 30:
        return False
    score = sum(1 for ind in NGINX_INDICATORS if ind in content)
    if score < 2:
        return False
    # Reject files that look like YAML/Helm values rather than nginx config.
    # A real nginx config has directive lines like "listen 80;" or block
    # openers like "server {" as actual statements, not just in comments.
    lines = content.strip().split("\n")
    non_comment_lines = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
    if not non_comment_lines:
        return False
    first_real = non_comment_lines[0]
    # If the first non-comment line is YAML-like, reject
    if re.match(r"^[\w\-]+:\s", first_real) and "server {" not in first_real:
        return False
    return True


def brace_balanced(content):
    """Check that braces are roughly balanced (within ±2 for partial configs)."""
    opens = content.count("{")
    closes = content.count("}")
    return abs(opens - closes) <= 2


# ── Main pipeline ───────────────────────────────────────────────────────────

def process_file(filepath, filename):
    """
    Returns list of (extracted_content, method_tag) tuples.
    """
    content = filepath.read_text(encoding="utf-8", errors="replace")
    fmt = classify(content, filename)

    if fmt == "raw":
        cleaned = normalize_raw(content)
        if looks_like_nginx(cleaned):
            return [(cleaned, "raw")], fmt
        return [], fmt

    if fmt == "jinja":
        cleaned = strip_jinja(content)
        cleaned = normalize_raw(cleaned)
        if looks_like_nginx(cleaned):
            return [(cleaned, "jinja_stripped")], fmt
        return [], fmt

    if fmt == "erb":
        cleaned = strip_erb(content)
        cleaned = normalize_raw(cleaned)
        if looks_like_nginx(cleaned):
            return [(cleaned, "erb_stripped")], fmt
        return [], fmt

    if fmt in ("shell_heredoc", "shell_script", "dockerfile"):
        configs = extract_from_shell(content)
        results = []
        for c in configs:
            c = normalize_raw(c)
            if looks_like_nginx(c):
                results.append((c, "shell_extracted"))
        # If heredoc extraction failed, try treating the whole thing as
        # a config that happens to have a shebang
        if not results:
            stripped = re.sub(r"^#!.*\n", "", content, count=1)
            stripped = normalize_raw(stripped)
            if looks_like_nginx(stripped) and brace_balanced(stripped):
                results.append((stripped, "shebang_stripped"))
        return results, fmt

    if fmt == "puppet":
        configs = extract_from_puppet(content)
        results = [(normalize_raw(c), "puppet_extracted") for c in configs if looks_like_nginx(c)]
        return results, fmt

    if fmt == "k8s_yaml":
        configs = extract_from_yaml(content)
        results = [(normalize_raw(c), "yaml_extracted") for c in configs if looks_like_nginx(c)]
        return results, fmt

    if fmt == "k8s_yaml_jinja":
        stripped = strip_jinja(content)
        configs = extract_from_yaml(stripped)
        results = [(normalize_raw(c), "yaml_jinja_extracted") for c in configs if looks_like_nginx(c)]
        return results, fmt

    if fmt == "markdown":
        configs = extract_from_markdown(content)
        results = [(normalize_raw(c), "markdown_extracted") for c in configs if looks_like_nginx(c)]
        return results, fmt

    return [], fmt


def main():
    parser = argparse.ArgumentParser(description="Extract nginx configs from wrapper formats")
    parser.add_argument("--input-dir", default="corpus_out/nginx/raw", help="Input directory")
    parser.add_argument("--output-dir", default="corpus_out/nginx/extracted", help="Output directory")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load metadata for provenance
    meta_file = input_dir / "metadata.json"
    metadata_by_file = {}
    if meta_file.exists():
        with open(meta_file) as f:
            for entry in json.load(f):
                metadata_by_file[entry["local_file"]] = entry

    config_files = sorted(
        p for p in input_dir.iterdir()
        if p.is_file() and p.name != "metadata.json" and not p.name.startswith(".")
        and not p.is_dir()
    )

    stats = Counter()
    format_stats = Counter()
    method_stats = Counter()
    output_meta = []
    seen_hashes = set()
    skipped_dupes = 0
    failed = []

    print(f"Processing {len(config_files)} files from {input_dir}/")
    print(f"Output: {output_dir}/\n")

    for filepath in config_files:
        filename = filepath.name
        results, fmt = process_file(filepath, filename)
        format_stats[fmt] += 1

        if not results:
            stats["no_extract"] += 1
            failed.append((filename, fmt))
            continue

        for i, (content, method) in enumerate(results):
            h = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if h in seen_hashes:
                skipped_dupes += 1
                continue
            seen_hashes.add(h)

            suffix = f"__{i}" if len(results) > 1 else ""
            out_name = filepath.stem + suffix + ".conf"
            out_path = output_dir / out_name
            if out_path.exists():
                out_name = filepath.stem + suffix + "__" + h[:12] + ".conf"
                out_path = output_dir / out_name
                n = 1
                while out_path.exists():
                    out_name = filepath.stem + suffix + f"__{h[:12]}__{n}.conf"
                    out_path = output_dir / out_name
                    n += 1
            out_path.write_text(content, encoding="utf-8")

            method_stats[method] += 1
            stats["extracted"] += 1

            entry = {
                "original_file": filename,
                "local_file": out_name,
                "output_file": out_name,
                "method": method,
                "format": fmt,
                "sha256": h,
                "size": len(content),
            }
            if filename in metadata_by_file:
                entry["source"] = metadata_by_file[filename]
            output_meta.append(entry)

    # Write metadata
    with open(output_dir / "metadata.json", "w") as f:
        json.dump(output_meta, f, indent=1)

    # Report
    total = len(config_files)
    extracted = stats["extracted"]
    no_extract = stats["no_extract"]

    print(f"{'='*60}")
    print(f"RESULTS")
    print(f"{'='*60}")
    print(f"Input files:        {total}")
    print(f"Configs extracted:  {extracted} ({100*extracted//total}%)")
    print(f"Deduplicated:       {skipped_dupes}")
    print(f"No config found:    {no_extract}")
    print()

    print(f"FORMAT BREAKDOWN (input)")
    print(f"{'-'*40}")
    for fmt, count in format_stats.most_common():
        print(f"  {fmt:25s} {count:5d}")
    print()

    print(f"EXTRACTION METHOD (output)")
    print(f"{'-'*40}")
    for method, count in method_stats.most_common():
        print(f"  {method:25s} {count:5d}")
    print()

    if failed:
        print(f"FAILED EXTRACTIONS (first 20)")
        print(f"{'-'*40}")
        for name, fmt in failed[:20]:
            print(f"  [{fmt}] {name[:70]}")
    print()
    print(f"Output: {output_dir}/")
    print(f"Metadata: {output_dir / 'metadata.json'}")


if __name__ == "__main__":
    main()

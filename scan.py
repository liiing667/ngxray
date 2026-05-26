#!/usr/bin/env python3
"""
Scan nginx configs for known CVE patterns.

Rules are JSON files in rules/. The engine parses configs with nginx's own
tokenizer (via nginx_conf_parse) and evaluates each rule against the AST.

Usage:
    python3 scan.py nginx.conf
    python3 scan.py /etc/nginx/
    find /etc/nginx -name '*.conf' | python3 scan.py -
    ./build/nginx_conf_parse - < list | python3 scan.py --jsonl -
"""

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

BASE = Path(__file__).resolve().parent
PARSER = str(BASE / "build" / "nginx_conf_parse")
RULES_DIR = str(BASE / "rules")

PHASE_BOUNDARY_DIRECTIVES = frozenset({
    "http", "stream", "mail", "events", "server", "upstream",
    "location", "limit_except", "map", "geo", "split_clients",
    "types",
})


# ── Data ────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    message: str
    cve: str = ""
    details: str = ""


# ── AST helpers ─────────────────────────────────────────────────────────

def children(node):
    return node.get("block", [])


def _match_name(directive, name):
    if isinstance(name, (list, tuple)):
        return directive in name
    return directive == name


def walk(nodes, name):
    """Walk the entire tree, yielding nodes whose directive matches name."""
    for n in nodes:
        if _match_name(n["directive"], name):
            yield n
        yield from walk(children(n), name)


def walk_rewrite_scope(nodes, name):
    """Walk nodes within the same rewrite-phase scope.

    Descends into if{} blocks (same rewrite engine) but stops at
    location{}, server{}, and other structural blocks that create a
    separate rewrite phase with a fresh engine.
    """
    for n in nodes:
        if _match_name(n["directive"], name):
            yield n
        if n["directive"] not in PHASE_BOUNDARY_DIRECTIVES:
            yield from walk_rewrite_scope(children(n), name)


def walk_rewrite_scope_all(nodes):
    """Walk every node in source order within one rewrite-phase scope."""
    for n in nodes:
        yield n
        if n["directive"] not in PHASE_BOUNDARY_DIRECTIVES:
            yield from walk_rewrite_scope_all(children(n))


def walk_all(nodes):
    """Walk every node in source order, including structural sub-blocks."""
    for n in nodes:
        yield n
        yield from walk_all(children(n))


def all_blocks(nodes):
    """Yield (block_contents, parent_node) for every block in the tree."""
    for n in nodes:
        blk = children(n)
        if blk:
            yield blk, n
            yield from all_blocks(blk)


# ── Regex structure analysis ───────────────────────────────────────────

def parse_capture_groups(regex):
    """
    Parse a PCRE regex and return a dict mapping capturing group number to
    its (open_pos, close_pos) in the regex string. Correctly skips escaped
    parens, character classes, and non-capturing groups (?:, (?=, etc.).
    """
    groups = {}
    stack = []
    group_num = 0
    i = 0
    n = len(regex)

    while i < n:
        c = regex[i]

        if c == '\\':
            i += 2
            continue

        if c == '[':
            i += 1
            if i < n and regex[i] == '^':
                i += 1
            if i < n and regex[i] == ']':
                i += 1
            while i < n and regex[i] != ']':
                if regex[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue

        if c == '(':
            i += 1
            if i < n and regex[i] == '?':
                stack.append((None, i - 1))
                i += 1
            else:
                group_num += 1
                stack.append((group_num, i - 1))
            continue

        if c == ')':
            if stack:
                gn, start = stack.pop()
                if gn is not None:
                    groups[gn] = (start, i)
            i += 1
            continue

        i += 1

    return groups


def rewrite_output_prefix(replacement):
    """Extract the literal URI prefix from a rewrite replacement.

    Strips the query string (after '?') and returns everything before the
    first $variable reference.  For '/index.php?q=$1' this returns
    '/index.php'.  Returns '' if the replacement starts with a variable.
    """
    uri = replacement.split('?')[0]
    return re.split(r'\$[0-9a-zA-Z_]', uri)[0]


def regex_literal_prefix(pattern):
    """Extract the required literal prefix from a regex pattern.

    For '^/stage/(.*)', returns 'stage'.  Returns '' if the regex starts
    with a wildcard or alternation.
    """
    m = re.match(r'^\^/?([a-zA-Z0-9_.\-]+)', pattern)
    return m.group(1) if m else ''


def rewrites_can_chain(node_a, node_b):
    """Check if rewrite A's output URI could plausibly match rewrite B's regex.

    Uses literal-prefix comparison: if A rewrites to '/index.php?...' and B
    requires '^/admin/', the prefixes are incompatible and chaining is
    impossible.  Returns True (may chain) when the check is inconclusive.
    """
    args_a = node_a.get("args", [])
    args_b = node_b.get("args", [])
    if len(args_a) < 2 or len(args_b) < 1:
        return True

    replacement = args_a[1]

    # A replacement starting with http://, https://, or $scheme is an implicit
    # redirect — nginx returns 3xx and stops processing.  No chaining.
    if re.match(r'(?:https?://|\$scheme)', replacement):
        return False

    out_prefix = rewrite_output_prefix(replacement).lstrip('/')
    rx_prefix = regex_literal_prefix(args_b[0])

    if not out_prefix or not rx_prefix:
        return True

    return out_prefix.startswith(rx_prefix) or rx_prefix.startswith(out_prefix)


def has_overlapping_refs(regex, replacement):
    """
    Check whether a rewrite regex+replacement has overlapping referenced
    captures. Returns True if any two $N references in the replacement
    correspond to capture groups where one physically contains the other.
    """
    groups = parse_capture_groups(regex)
    refs = set(int(m.group(1)) for m in re.finditer(r'\$([1-9])', replacement))
    if len(refs) < 2:
        return False

    ref_list = sorted(refs)
    for i in range(len(ref_list)):
        for j in range(i + 1, len(ref_list)):
            a, b = ref_list[i], ref_list[j]
            if a not in groups or b not in groups:
                continue
            a_s, a_e = groups[a]
            b_s, b_e = groups[b]
            if (a_s <= b_s and a_e >= b_e) or (b_s <= a_s and b_e >= a_e):
                return True
    return False


# ── Condition evaluator ────────────────────────────────────────────────

def check_condition(value, cond, collected=None):
    """
    Test a string value against a condition object.

    Supported keys:
      contains: str         — substring match
      regex: str            — regex search
      not_regex: str        — regex must NOT match
      any_of: [str, ...]    — value equals one of
      extract: str          — regex pattern; pull all matches for min_unique
      min_unique: int       — (with extract) require >= N distinct matches
      contains_collected: bool — value contains a collected variable
      capture_before_collected: bool — a $N ref appears before a collected var
    """
    if isinstance(cond, str):
        return value == cond

    extract_pattern = cond.get("extract")
    min_unique = cond.get("min_unique")

    for key, expected in cond.items():
        if key in ("extract", "min_unique"):
            continue
        if key == "contains":
            if expected not in value:
                return False
        elif key == "regex":
            if not re.search(expected, value):
                return False
        elif key == "not_regex":
            if re.search(expected, value):
                return False
        elif key == "any_of":
            if value not in expected:
                return False
        elif key == "contains_collected":
            if expected and collected:
                if not any(v in value for v in collected):
                    return False
            elif expected:
                return False
        elif key == "capture_before_collected":
            if expected and collected:
                cap_positions = [m.start() for m in re.finditer(r'\$[1-9]', value)]
                col_positions = []
                for v in collected:
                    for m in re.finditer(re.escape(v), value):
                        col_positions.append(m.start())
                if not cap_positions or not col_positions:
                    return False
                if min(cap_positions) >= min(col_positions):
                    return False

    if extract_pattern is not None and min_unique is not None:
        matches = set(re.findall(extract_pattern, value))
        if len(matches) < min_unique:
            return False

    return True


def match_directive(node, pattern, collected=None):
    """Check if a directive node matches a pattern."""
    if "directive_any_of" in pattern:
        if node["directive"] not in pattern["directive_any_of"]:
            return False
    elif "directive" in pattern and node["directive"] != pattern["directive"]:
        return False

    args = node.get("args", [])

    # Positional arg checks
    for idx_str, cond in pattern.get("args", {}).items():
        idx = int(idx_str)
        if idx >= len(args):
            return False
        if not check_condition(args[idx], cond, collected):
            return False

    # max_args: reject if directive has more than N args (e.g. rewrite with flag)
    if "max_args" in pattern:
        if len(args) > pattern["max_args"]:
            return False

    # overlapping_refs: verify referenced captures in args[1] actually overlap
    # in the regex at args[0]
    if pattern.get("overlapping_refs"):
        if len(args) < 2 or not has_overlapping_refs(args[0], args[1]):
            return False

    # any_arg: condition must match at least one arg
    if "any_arg" in pattern:
        if not any(check_condition(a, pattern["any_arg"], collected)
                   for a in args):
            return False

    # or: at least one alternative must match
    if "or" in pattern:
        if not any(match_or_branch(node, branch) for branch in pattern["or"]):
            return False

    return True


def match_or_branch(node, branch):
    """Evaluate one branch of an 'or' condition."""
    args = node.get("args", [])

    for idx_str, cond in branch.get("args", {}).items():
        idx = int(idx_str)
        if idx >= len(args):
            return False
        if not check_condition(args[idx], cond):
            return False

    if "any_arg_from" in branch and "any_of" in branch:
        start = branch["any_arg_from"]
        if not any(a in branch["any_of"] for a in args[start:]):
            return False

    return True


# ── Rule evaluation ────────────────────────────────────────────────────

def collect_phase(nodes, collect_spec):
    """Run the collect phase: find directives and extract values."""
    collected = set()
    directive = collect_spec["directive"]
    child_regex = collect_spec.get("child_regex")
    extract = collect_spec.get("extract", "")

    for node in walk(nodes, directive):
        blk = children(node)

        if child_regex:
            if not any(re.match(child_regex, c["directive"]) for c in blk):
                continue

        parts = extract.split(".")
        obj = node
        for p in parts:
            if isinstance(obj, dict):
                obj = obj.get(p, [])
            elif isinstance(obj, list):
                try:
                    obj = obj[int(p)]
                except (IndexError, ValueError):
                    obj = None
                    break
            else:
                obj = None
                break

        if obj and isinstance(obj, str):
            collected.add(obj)

    return collected


def _get_candidates(block, pat):
    """Get (source_order, node) candidates for a pattern within a block."""
    scope = pat.get("scope", "siblings")
    dname = pat.get("directive_any_of", pat.get("directive"))

    if scope == "subtree":
        nodes = walk_rewrite_scope_all(block)
    elif scope == "full_subtree":
        nodes = walk_all(block)
    else:
        nodes = iter(block)

    return [(i, n) for i, n in enumerate(nodes)
            if _match_name(n["directive"], dname)]


def eval_rule(rule, nodes, filepath):
    """Evaluate a single JSON rule against a parsed config."""
    findings = []
    patterns = rule["match"]
    collected = None

    if "collect" in rule:
        collected = collect_phase(nodes, rule["collect"])
        if not collected:
            return findings

    if len(patterns) == 1:
        pat = patterns[0]
        dname = pat.get("directive_any_of", pat.get("directive"))
        for node in walk(nodes, dname):
            if match_directive(node, pat, collected):
                findings.append(make_finding(rule, node, [node], filepath))

    else:
        ordered = rule.get("ordered", False)
        for block, parent in all_blocks(nodes):
            matched = []
            last_pos = -1
            for pat in patterns:
                hit = None
                candidates = _get_candidates(block, pat)
                for node_pos, node in candidates:
                    if match_directive(node, pat, collected):
                        if ordered:
                            if node_pos <= last_pos:
                                continue
                            last_pos = node_pos
                        hit = node
                        break
                if hit is None:
                    break
                matched.append(hit)

            if len(matched) != len(patterns):
                continue

            if rule.get("chainable"):
                if not rewrites_can_chain(matched[0], matched[1]):
                    continue

            findings.append(make_finding(rule, matched[0], matched,
                                         filepath))

    return findings


def make_finding(rule, primary, matched, filepath):
    detail_parts = []
    for m in matched:
        args_str = " ".join(m.get("args", []))
        detail_parts.append(f"{m['directive']} {args_str}")

    return Finding(
        rule=rule["id"],
        severity=rule["severity"],
        file=filepath,
        line=primary["line"],
        message=rule["message"],
        cve=rule.get("cve", ""),
        details="\n".join(detail_parts),
    )


# ── Rule loading ───────────────────────────────────────────────────────

def load_rules(rules_dir=RULES_DIR):
    rules = []
    for f in sorted(Path(rules_dir).glob("*.json")):
        with open(f) as fh:
            rule = json.load(fh)
        rules.append(rule)
    return rules


# ── Config parsing ─────────────────────────────────────────────────────

def parse_file(filepath):
    try:
        r = subprocess.run([PARSER, filepath],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return None
        return json.loads(r.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError,
            FileNotFoundError):
        return None


# ── Self-test ──────────────────────────────────────────────────────────

def parse_snippet(snippet):
    """Parse a config snippet by writing to a temp file and invoking the parser."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        f.write(snippet + "\n")
        f.flush()
        ast = parse_file(f.name)
        os.unlink(f.name)
        return ast


def run_tests(rules_dir=RULES_DIR):
    """Run embedded tests from all rule JSON files. Returns (passed, failed)."""
    rules = load_rules(rules_dir)
    passed = failed = 0

    for rule in rules:
        tests = rule.get("tests")
        if not tests:
            continue

        rule_id = rule["id"]

        for snippet in tests.get("vulnerable", []):
            ast = parse_snippet(snippet)
            if ast is None:
                print(f"  FAIL [{rule_id}] parse error on vulnerable config:")
                print(f"    {snippet[:100]}")
                failed += 1
                continue
            findings = eval_rule(rule, ast, "<test>")
            if findings:
                passed += 1
            else:
                print(f"  FAIL [{rule_id}] expected finding but got none:")
                print(f"    {snippet[:100]}")
                failed += 1

        for snippet in tests.get("safe", []):
            ast = parse_snippet(snippet)
            if ast is None:
                print(f"  FAIL [{rule_id}] parse error on safe config:")
                print(f"    {snippet[:100]}")
                failed += 1
                continue
            findings = eval_rule(rule, ast, "<test>")
            if not findings:
                passed += 1
            else:
                print(f"  FAIL [{rule_id}] expected no finding but got:")
                print(f"    {snippet[:100]}")
                print(f"    finding: {findings[0].message}")
                failed += 1

    return passed, failed


# ── Main ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Scan nginx configs for CVEs")
    ap.add_argument("input", nargs="?", default="-",
                    help="config file, directory, or - for stdin filenames")
    ap.add_argument("--jsonl", action="store_true",
                    help="input is pre-parsed JSONL from nginx_conf_parse")
    ap.add_argument("--json", action="store_true",
                    help="output findings as JSON array")
    ap.add_argument("--rules", default=RULES_DIR,
                    help="rules directory (default: rules/)")
    ap.add_argument("--test", action="store_true",
                    help="run embedded tests from rule files and exit")
    args = ap.parse_args()

    if args.test:
        passed, failed = run_tests(args.rules)
        total = passed + failed
        print(f"{passed}/{total} tests passed")
        sys.exit(1 if failed else 0)

    rules = load_rules(args.rules)
    all_findings = []
    scanned = failed = 0

    def scan_one(ast, filepath):
        for rule in rules:
            all_findings.extend(eval_rule(rule, ast, filepath))

    if args.jsonl:
        stream = sys.stdin if args.input == "-" else open(args.input)
        for line in stream:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("error"):
                failed += 1
                continue
            scanned += 1
            scan_one(rec.get("config", []), rec.get("file", "?"))

    elif args.input == "-" and not args.jsonl:
        for line in sys.stdin:
            path = line.strip()
            if not path:
                continue
            ast = parse_file(path)
            if ast is None:
                failed += 1
                continue
            scanned += 1
            scan_one(ast, path)

    elif os.path.isdir(args.input):
        for root, _, files in os.walk(args.input):
            for f in sorted(files):
                if not f.endswith(".conf"):
                    continue
                path = os.path.join(root, f)
                ast = parse_file(path)
                if ast is None:
                    failed += 1
                    continue
                scanned += 1
                scan_one(ast, path)

    else:
        ast = parse_file(args.input)
        if ast is None:
            print(f"parse failed: {args.input}", file=sys.stderr)
            sys.exit(1)
        scanned = 1
        scan_one(ast, args.input)

    if args.json:
        json.dump([asdict(f) for f in all_findings], sys.stdout, indent=2)
        print()
    else:
        if not all_findings:
            print("No vulnerabilities found.", file=sys.stderr)
        else:
            for f in all_findings:
                cve = f" ({f.cve})" if f.cve else ""
                print(f"[{f.severity}] {f.rule}{cve}")
                print(f"  {f.file}:{f.line}")
                print(f"  {f.message}")
                if f.details:
                    for dl in f.details.split("\n"):
                        print(f"    {dl}")
                print()

        print(f"{len(all_findings)} finding(s) in "
              f"{scanned} config(s) ({failed} failed)",
              file=sys.stderr)


if __name__ == "__main__":
    main()

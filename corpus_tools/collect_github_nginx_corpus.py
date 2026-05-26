#!/usr/bin/env python3
"""
Collect nginx configuration material from public GitHub code search.

It searches direct nginx config files, templates, Kubernetes/Helm YAML, docs,
Dockerfiles, and shell scripts that embed or generate nginx configs.

It reads GITHUB_TOKEN from the process environment or from .env in the current
working directory. The token is never printed.

Output layout:
  corpus_out/nginx/raw/metadata.json  source provenance
  corpus_out/nginx/raw/*              raw GitHub files
  corpus_out/nginx/state.json         resumable search state
  corpus_out/nginx/candidates.jsonl   every accepted raw-source candidate
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

import requests


API_SEARCH = "https://api.github.com/search/code"
RAW_GH = "https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"

USER_AGENT = "nginx-config-corpus-collector/2.0"

NGINX_PATTERNS = [
    r"\bworker_processes\b",
    r"\bevents\s*\{",
    r"\bhttp\s*\{",
    r"\bserver\s*\{",
    r"\blocation\s+[^;\n{]+\{",
    r"\bupstream\s+\S+\s*\{",
    r"\bmap\s+\S+\s+\S+\s*\{",
    r"\bgeo\s+\S+\s*\{",
    r"\blisten\s+[^;\n]+;",
    r"\bserver_name\s+[^;\n]+;",
    r"\bproxy_pass\s+[^;\n]+;",
    r"\bfastcgi_pass\s+[^;\n]+;",
    r"\buwsgi_pass\s+[^;\n]+;",
    r"\bscgi_pass\s+[^;\n]+;",
    r"\bgrpc_pass\s+[^;\n]+;",
    r"\brewrite\s+[^;\n]+;",
    r"\btry_files\s+[^;\n]+;",
    r"\bproxy_set_header\s+[^;\n]+;",
    r"\badd_header\s+[^;\n]+;",
    r"\bssl_certificate\s+[^;\n]+;",
    r"\berror_page\s+[^;\n]+;",
    r"\baccess_log\s+[^;\n]+;",
    r"\berror_log\s+[^;\n]+;",
    r"\binclude\s+[^;\n]*nginx[^;\n]*;",
]

NGINX_RE = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in NGINX_PATTERNS]

QUERY_TERMS = [
    # GitHub's own language classifier for nginx configs.
    'nginx language:Nginx',
    '"server {" language:Nginx',
    '"proxy_pass" language:Nginx',
    '"rewrite " language:Nginx',
    '"map " language:Nginx',
    '"fastcgi_pass" language:Nginx',

    # Filename-focused config searches.
    'nginx filename:nginx.conf',
    '"server {" filename:nginx.conf',
    '"proxy_pass" filename:nginx.conf',
    '"rewrite " filename:nginx.conf',
    '"map " filename:nginx.conf',
    '"server {" filename:default.conf',
    '"proxy_pass" filename:default.conf',
    '"try_files" filename:default.conf',
    '"server_name" filename:default.conf',
    '"server {" filename:site.conf',
    '"server {" filename:vhost.conf',
    '"proxy_pass" filename:proxy.conf',
    '"upstream " filename:upstream.conf',
    '"ssl_certificate" filename:ssl.conf',

    # Generic .conf files with nginx-only directives.
    '"worker_processes" extension:conf',
    '"server_name" "listen " extension:conf',
    '"server {" "location " extension:conf',
    '"proxy_pass" "server {" extension:conf',
    '"proxy_set_header" "proxy_pass" extension:conf',
    '"fastcgi_pass" "location" extension:conf',
    '"uwsgi_pass" "server {" extension:conf',
    '"scgi_pass" "server {" extension:conf',
    '"grpc_pass" extension:conf',
    '"try_files" "$uri" extension:conf',
    '"rewrite " "server {" extension:conf',
    '"return 301" "server {" extension:conf',
    '"map " "server {" extension:conf',
    '"limit_req_zone" extension:conf',
    '"proxy_cache_path" extension:conf',
    '"ssl_certificate" "ssl_certificate_key" extension:conf',
    '"auth_request" "location" extension:conf',
    '"sub_filter" "server {" extension:conf',

    # Path-focused config searches.
    'nginx path:conf.d extension:conf',
    'nginx path:sites-available extension:conf',
    'nginx path:sites-enabled extension:conf',
    'nginx path:etc/nginx extension:conf',
    'nginx path:docker/nginx extension:conf',
    'nginx path:deploy/nginx extension:conf',
    'nginx path:nginx/conf extension:conf',
    'nginx path:roles/nginx extension:j2',
    'nginx path:templates/nginx',

    # Template formats.
    '"server {" nginx extension:j2',
    '"proxy_pass" nginx extension:j2',
    '"server {" nginx extension:jinja',
    '"server {" nginx extension:template',
    '"proxy_pass" nginx extension:template',
    '"server {" nginx extension:tmpl',
    '"server {" nginx extension:erb',
    '"proxy_pass" nginx extension:erb',
    '"server {" nginx extension:tpl',
    '"server {" nginx extension:mustache',
    '"server {" nginx extension:ctmpl',

    # Dockerfiles and shell generation.
    'nginx filename:Dockerfile "nginx.conf"',
    'nginx filename:Dockerfile "default.conf"',
    'nginx filename:Dockerfile "/etc/nginx"',
    'nginx filename:Dockerfile "conf.d/default.conf"',
    'nginx filename:Dockerfile "server {"',
    'nginx filename:Dockerfile "location /"',
    'nginx filename:Dockerfile "proxy_pass"',
    'nginx filename:Dockerfile "cat <<"',
    'nginx filename:Dockerfile "tee /etc/nginx"',
    'nginx filename:Dockerfile "COPY <<"',
    'nginx filename:Dockerfile "ADD <<"',
    'nginx filename:Dockerfile "envsubst"',
    'nginx extension:sh "/etc/nginx"',
    'nginx extension:sh "nginx.conf"',
    'nginx extension:sh "default.conf"',
    'nginx extension:sh "server {"',
    'nginx extension:sh "proxy_pass"',
    'nginx extension:sh "cat <<"',
    'nginx extension:bash "/etc/nginx"',
    'nginx extension:bash "server {"',
    'nginx extension:zsh "/etc/nginx"',
    'nginx filename:entrypoint.sh "/etc/nginx"',
    'nginx filename:docker-entrypoint.sh "/etc/nginx"',
    'nginx filename:setup.sh "/etc/nginx"',
    'nginx filename:install.sh "/etc/nginx"',

    # Kubernetes, Helm, Compose, and docs with embedded config blocks/snippets.
    'nginx extension:yaml "nginx.conf:"',
    'nginx extension:yml "nginx.conf:"',
    'nginx extension:yaml "default.conf:"',
    'nginx extension:yml "default.conf:"',
    'nginx extension:yaml "server {" "proxy_pass"',
    'nginx extension:yml "server {" "proxy_pass"',
    'nginx extension:yaml "nginx.ingress.kubernetes.io/configuration-snippet"',
    'nginx extension:yml "nginx.ingress.kubernetes.io/configuration-snippet"',
    'nginx extension:yaml "nginx.ingress.kubernetes.io/server-snippet"',
    'nginx extension:yml "nginx.ingress.kubernetes.io/server-snippet"',
    'nginx extension:yaml "nginx.ingress.kubernetes.io/location-snippet"',
    'nginx extension:yml "nginx.ingress.kubernetes.io/location-snippet"',
    'nginx filename:values.yaml "server {"',
    'nginx filename:values.yaml "configuration-snippet"',
    'nginx filename:docker-compose.yml "/etc/nginx"',
    'nginx filename:docker-compose.yaml "/etc/nginx"',
    'nginx extension:md "server {" "proxy_pass"',
    'nginx extension:md "nginx.conf" "server {"',
    'nginx extension:rst "nginx.conf" "server {"',
]


class StopCrawl(Exception):
    pass


@dataclass(frozen=True)
class Candidate:
    owner: str
    repo: str
    path: str
    ref: str
    html_url: str
    api_url: str
    query: str
    page: int
    relation: str = "search_result"
    related_from: str | None = None

    @property
    def repo_full(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def file_key(self) -> str:
        return f"{self.owner}/{self.repo}/{self.path}"


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def auth_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }


def raw_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
    }


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def safe_name(owner: str, repo: str, path: str, h: str) -> str:
    name = f"{owner}__{repo}__{path.replace('/', '__')}"
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    if len(name) > 220:
        suffix = Path(path).suffix or ".txt"
        name = f"{name[:180]}__{h[:16]}{suffix}"
    return name


def query_key(query: str, page: int) -> str:
    return f"{hashlib.sha256(query.encode()).hexdigest()[:16]}:{page}"


def load_metadata(meta_file: Path) -> list[dict]:
    if not meta_file.exists():
        return []
    with meta_file.open() as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{meta_file} must contain a JSON list")
    return data


def save_metadata(meta_file: Path, metadata: list[dict]) -> None:
    tmp = meta_file.with_suffix(".json.tmp")
    with tmp.open("w") as f:
        json.dump(metadata, f, indent=1, sort_keys=True)
    tmp.replace(meta_file)


def load_state(state_file: Path) -> dict:
    if not state_file.exists():
        return {"completed_pages": [], "invalid_queries": []}
    with state_file.open() as f:
        state = json.load(f)
    state.setdefault("completed_pages", [])
    state.setdefault("invalid_queries", [])
    return state


def save_state(state_file: Path, state: dict) -> None:
    tmp = state_file.with_suffix(".json.tmp")
    state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with tmp.open("w") as f:
        json.dump(state, f, indent=1, sort_keys=True)
    tmp.replace(state_file)


def nginx_score(content: str) -> int:
    return sum(1 for rx in NGINX_RE if rx.search(content))


def strong_path_hint(path: str) -> bool:
    p = path.lower()
    base = Path(p).name
    suffix = "".join(Path(p).suffixes)
    if "nginx" in p or "/conf.d/" in p or "sites-available" in p or "sites-enabled" in p:
        return True
    if base in {"default.conf", "site.conf", "vhost.conf", "proxy.conf", "ssl.conf"}:
        return True
    if suffix in {".conf", ".conf.j2", ".conf.erb", ".conf.template", ".conf.tmpl"}:
        return True
    return False


def wrapper_path_hint(path: str) -> bool:
    p = path.lower()
    base = Path(p).name
    suffix = Path(p).suffix
    if base.startswith("dockerfile"):
        return True
    if suffix in {".sh", ".bash", ".zsh", ".yaml", ".yml", ".md", ".rst", ".pp"}:
        return True
    if base in {"values.yaml", "values.yml", "docker-compose.yml", "docker-compose.yaml"}:
        return True
    return False


def looks_relevant(path: str, content: str) -> bool:
    if not content or len(content.strip()) < 20:
        return False
    if "\x00" in content[:4096]:
        return False

    score = nginx_score(content)
    lower = content.lower()

    if strong_path_hint(path) and score >= 1:
        return True
    if score >= 2:
        return True
    if "nginx" in lower and score >= 1:
        return True
    if "/etc/nginx" in lower and ("nginx" in lower or score >= 1):
        return True
    if "nginx.ingress.kubernetes.io/" in lower and score >= 1:
        return True
    if wrapper_path_hint(path) and "nginx" in lower and any(t in lower for t in ("server {", "proxy_pass", "location ", "nginx.conf", "default.conf")):
        return True
    return False


def github_search(session: requests.Session, query: str, page: int, per_page: int, max_rate_wait: int) -> dict | None:
    while True:
        r = session.get(API_SEARCH, params={"q": query, "per_page": per_page, "page": page}, timeout=45)

        if r.status_code in (403, 429):
            msg = ""
            try:
                msg = r.json().get("message", "")
            except Exception:
                msg = r.text[:200]
            remaining = r.headers.get("X-RateLimit-Remaining")
            reset = int(r.headers.get("X-RateLimit-Reset", "0") or "0")
            wait = max(0, reset - int(time.time()) + 3)
            if remaining == "0" or "rate limit" in msg.lower() or "secondary rate" in msg.lower():
                if wait <= max_rate_wait:
                    print(f"  rate limited; sleeping {wait}s")
                    time.sleep(wait)
                    continue
                print(f"  rate limited for {wait}s; stopping crawl cleanly")
                raise StopCrawl()
            print(f"  search denied: HTTP {r.status_code}: {msg[:160]}")
            return None

        if r.status_code == 422:
            try:
                msg = r.json().get("message", "")
            except Exception:
                msg = r.text[:200]
            print(f"  invalid query: {msg[:160]}")
            return None

        if r.status_code >= 500:
            print(f"  transient search error HTTP {r.status_code}; sleeping 10s")
            time.sleep(10)
            continue

        r.raise_for_status()
        return r.json()


def candidate_from_item(item: dict, query: str, page: int) -> Candidate | None:
    repo_obj = item.get("repository") or {}
    full = repo_obj.get("full_name") or ""
    if "/" not in full:
        return None
    owner, repo = full.split("/", 1)
    path = item.get("path")
    if not path:
        return None
    ref = repo_obj.get("default_branch") or "HEAD"
    return Candidate(
        owner=owner,
        repo=repo,
        path=path,
        ref=ref,
        html_url=item.get("html_url") or "",
        api_url=item.get("url") or "",
        query=query,
        page=page,
    )


def raw_url(cand: Candidate) -> str:
    return RAW_GH.format(
        owner=quote(cand.owner, safe=""),
        repo=quote(cand.repo, safe=""),
        ref=quote(cand.ref, safe=""),
        path=quote(cand.path, safe="/"),
    )


def decode_content_api(data: dict) -> str | None:
    if data.get("type") != "file":
        return None
    encoding = data.get("encoding")
    content = data.get("content")
    if encoding == "base64" and content:
        raw = base64.b64decode(content)
        return raw.decode("utf-8", errors="replace")
    download_url = data.get("download_url")
    if download_url:
        rr = requests.get(download_url, timeout=30, headers={"User-Agent": USER_AGENT})
        if rr.status_code == 200:
            return rr.content.decode("utf-8", errors="replace")
    return None


def fetch_candidate(cand: Candidate, token: str, max_bytes: int) -> tuple[Candidate, str | None, str | None]:
    headers = raw_headers(token)
    url = raw_url(cand)
    try:
        r = requests.get(url, timeout=30, headers=headers, stream=True)
        if r.status_code == 200:
            length = int(r.headers.get("Content-Length", "0") or "0")
            if length and length > max_bytes:
                return cand, None, f"too_large:{length}"
            raw = r.raw.read(max_bytes + 1, decode_content=True)
            if len(raw) > max_bytes:
                return cand, None, f"too_large:{len(raw)}"
            return cand, raw.decode("utf-8", errors="replace"), None
    except requests.RequestException as e:
        raw_error = f"raw_error:{type(e).__name__}"
    else:
        raw_error = f"raw_http:{r.status_code}"

    if not cand.api_url:
        return cand, None, raw_error

    try:
        rr = requests.get(cand.api_url, timeout=30, headers=auth_headers(token))
        if rr.status_code != 200:
            return cand, None, f"{raw_error};api_http:{rr.status_code}"
        return cand, decode_content_api(rr.json()), None
    except requests.RequestException as e:
        return cand, None, f"{raw_error};api_error:{type(e).__name__}"


def related_paths_from_wrapper(path: str, content: str) -> list[str]:
    lower = content.lower()
    if "/etc/nginx" not in lower and "nginx.conf" not in lower and "default.conf" not in lower:
        return []

    candidates: list[str] = []
    # Dockerfile COPY/ADD sources directed at nginx destinations.
    copy_re = re.compile(
        r"(?im)^\s*(?:COPY|ADD)\s+(?:--[^\s]+\s+)*(?P<src>[^\s]+)\s+(?P<dst>[^\n#]+)"
    )
    for m in copy_re.finditer(content):
        src = m.group("src").strip().strip('"').strip("'")
        dst = m.group("dst").strip().strip('"').strip("'")
        if "nginx" not in dst.lower():
            continue
        if any(ch in src for ch in "*?[]") or "://" in src or src.startswith("--"):
            continue
        candidates.append(src)

    # Shell copy/install sources into /etc/nginx.
    cp_re = re.compile(
        r"(?im)\b(?:cp|install)\s+(?:-[^\s]+\s+)*(?P<src>[^\s;]+)\s+(?P<dst>/[^\s;]*nginx[^\s;]*)"
    )
    for m in cp_re.finditer(content):
        src = m.group("src").strip().strip('"').strip("'")
        if any(ch in src for ch in "*?[]${}") or "://" in src:
            continue
        candidates.append(src)

    base_dir = str(Path(path).parent)
    results: list[str] = []
    for src in candidates:
        if not src or src in {".", "./"}:
            continue
        src = src.lstrip("./")
        options = [src]
        if base_dir not in {"", "."}:
            options.append(str(Path(base_dir) / src))
        for opt in options:
            cleaned = str(Path(opt)).replace("\\", "/")
            if cleaned.startswith("../"):
                continue
            if cleaned not in results:
                results.append(cleaned)
    return results[:8]


def write_candidate_log(path: Path, entry: dict) -> None:
    with path.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def accept_and_store(
    cand: Candidate,
    content: str,
    raw_dir: Path,
    metadata: list[dict],
    seen_hashes: set[str],
    seen_keys: set[str],
) -> dict | None:
    if not looks_relevant(cand.path, content):
        return None

    h = content_hash(content)
    if h in seen_hashes:
        return None
    seen_hashes.add(h)
    seen_keys.add(cand.file_key)

    fname = safe_name(cand.owner, cand.repo, cand.path, h)
    target = raw_dir / fname
    if target.exists():
        stem = target.stem
        suffix = target.suffix
        target = raw_dir / f"{stem}__{h[:12]}{suffix}"
        fname = target.name
    target.write_text(content, encoding="utf-8", errors="replace")

    entry = {
        "source": "github_code_search",
        "owner": cand.owner,
        "repo": cand.repo,
        "path": cand.path,
        "ref": cand.ref,
        "html_url": cand.html_url,
        "api_url": cand.api_url,
        "query": cand.query,
        "page": cand.page,
        "relation": cand.relation,
        "related_from": cand.related_from,
        "sha256": h,
        "local_file": fname,
        "size": len(content),
        "nginx_score": nginx_score(content),
    }
    metadata.append(entry)
    return entry


def dedupe_queries(queries: Iterable[str]) -> list[str]:
    out = []
    seen = set()
    for q in queries:
        q = " ".join(q.split())
        if q not in seen:
            out.append(q)
            seen.add(q)
    return out


def load_query_file(path: Path) -> list[str]:
    queries = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            queries.append(line)
    return queries


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect public nginx config material via GitHub code search")
    parser.add_argument("--output-dir", default="corpus_out/nginx", help="Output root")
    parser.add_argument("--target", type=int, default=20000, help="Stop after this many accepted raw files")
    parser.add_argument("--query-file", default=None, help="Optional newline-delimited query file")
    parser.add_argument("--per-page", type=int, default=100, help="GitHub search page size")
    parser.add_argument("--page-limit", type=int, default=10, help="Max pages per query; GitHub exposes at most 10x100")
    parser.add_argument("--max-queries", type=int, default=0, help="Limit queries for testing; 0 means all")
    parser.add_argument("--workers", type=int, default=8, help="Parallel raw downloads per search page")
    parser.add_argument("--sleep", type=float, default=2.1, help="Delay between search API requests")
    parser.add_argument("--max-rate-wait", type=int, default=90, help="Stop instead of sleeping longer than this many seconds")
    parser.add_argument("--max-bytes", type=int, default=2_000_000, help="Skip raw files larger than this")
    parser.add_argument("--deadline-seconds", type=int, default=0, help="Optional wall-clock deadline for this run")
    parser.add_argument("--env-file", default=".env", help="File to load GITHUB_TOKEN from")
    args = parser.parse_args()

    load_env_file(Path(args.env_file))
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print("GITHUB_TOKEN or GH_TOKEN is required in the environment or .env", file=sys.stderr)
        return 2

    out_root = Path(args.output_dir)
    raw_dir = out_root / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    state_file = out_root / "state.json"
    meta_file = raw_dir / "metadata.json"
    candidate_log = out_root / "candidates.jsonl"

    metadata = load_metadata(meta_file)
    seen_hashes = {e["sha256"] for e in metadata if "sha256" in e}
    seen_keys = {f"{e['owner']}/{e['repo']}/{e['path']}" for e in metadata if all(k in e for k in ("owner", "repo", "path"))}
    state = load_state(state_file)
    completed_pages = set(state.get("completed_pages", []))
    invalid_queries = set(state.get("invalid_queries", []))

    queries = load_query_file(Path(args.query_file)) if args.query_file else list(QUERY_TERMS)
    queries = dedupe_queries(queries)
    if args.max_queries:
        queries = queries[: args.max_queries]

    session = requests.Session()
    session.headers.update(auth_headers(token))

    started = time.monotonic()
    accepted = len(metadata)
    print(f"Output raw dir: {raw_dir}")
    print(f"Existing accepted files: {accepted}")
    print(f"Queries scheduled: {len(queries)}")
    print(f"Target accepted files: {args.target}")

    def deadline_hit() -> bool:
        return bool(args.deadline_seconds and time.monotonic() - started >= args.deadline_seconds)

    try:
        for qi, query in enumerate(queries, 1):
            if accepted >= args.target or deadline_hit():
                break
            if query in invalid_queries:
                continue

            print(f"[{qi}/{len(queries)}] {query}")
            first_key = query_key(query, 1)
            if first_key in completed_pages:
                print("  page 1 already completed; continuing resume")

            first = github_search(session, query, 1, args.per_page, args.max_rate_wait)
            if first is None:
                invalid_queries.add(query)
                state["invalid_queries"] = sorted(invalid_queries)
                save_state(state_file, state)
                continue

            total = int(first.get("total_count") or 0)
            pages = min(args.page_limit, 10, max(1, math.ceil(total / args.per_page)))
            print(f"  total_count={total} pages={pages} incomplete={first.get('incomplete_results')}")

            page_payloads = {1: first}
            for page in range(1, pages + 1):
                if accepted >= args.target or deadline_hit():
                    break
                pkey = query_key(query, page)
                if pkey in completed_pages:
                    continue
                if page not in page_payloads:
                    time.sleep(args.sleep)
                    payload = github_search(session, query, page, args.per_page, args.max_rate_wait)
                    if payload is None:
                        break
                    page_payloads[page] = payload
                payload = page_payloads[page]

                items = payload.get("items") or []
                candidates = []
                for item in items:
                    cand = candidate_from_item(item, query, page)
                    if cand and cand.file_key not in seen_keys:
                        candidates.append(cand)

                page_accepted = 0
                related_queue: list[Candidate] = []
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    futures = [pool.submit(fetch_candidate, c, token, args.max_bytes) for c in candidates]
                    for fut in as_completed(futures):
                        cand, content, error = fut.result()
                        if not content:
                            continue
                        entry = accept_and_store(cand, content, raw_dir, metadata, seen_hashes, seen_keys)
                        if not entry:
                            continue
                        write_candidate_log(candidate_log, entry)
                        accepted += 1
                        page_accepted += 1

                        if wrapper_path_hint(cand.path):
                            for rel_path in related_paths_from_wrapper(cand.path, content):
                                rel = Candidate(
                                    owner=cand.owner,
                                    repo=cand.repo,
                                    path=rel_path,
                                    ref=cand.ref,
                                    html_url=f"https://github.com/{cand.owner}/{cand.repo}/blob/{cand.ref}/{rel_path}",
                                    api_url="",
                                    query=query,
                                    page=page,
                                    relation="referenced_by_wrapper",
                                    related_from=cand.path,
                                )
                                if rel.file_key not in seen_keys:
                                    related_queue.append(rel)

                # Fetch Dockerfile/shell COPY targets discovered from accepted wrappers.
                if related_queue and accepted < args.target:
                    with ThreadPoolExecutor(max_workers=min(args.workers, 4)) as pool:
                        futures = [pool.submit(fetch_candidate, c, token, args.max_bytes) for c in related_queue]
                        for fut in as_completed(futures):
                            cand, content, error = fut.result()
                            if not content:
                                continue
                            entry = accept_and_store(cand, content, raw_dir, metadata, seen_hashes, seen_keys)
                            if not entry:
                                continue
                            write_candidate_log(candidate_log, entry)
                            accepted += 1
                            page_accepted += 1

                completed_pages.add(pkey)
                state["completed_pages"] = sorted(completed_pages)
                save_metadata(meta_file, metadata)
                save_state(state_file, state)
                print(f"    page {page}: candidates={len(candidates)} accepted={page_accepted} total={accepted}")

            time.sleep(args.sleep)

    except StopCrawl:
        pass
    finally:
        state["completed_pages"] = sorted(completed_pages)
        state["invalid_queries"] = sorted(invalid_queries)
        save_metadata(meta_file, metadata)
        save_state(state_file, state)

    repos = len({f"{e['owner']}/{e['repo']}" for e in metadata})
    total_size = sum(int(e.get("size") or 0) for e in metadata)
    print()
    print(f"Done. Accepted raw files: {len(metadata)}")
    print(f"Unique repos: {repos}")
    print(f"Total raw size: {total_size / 1024 / 1024:.1f} MB")
    print(f"Metadata: {meta_file}")
    print(f"Resume: python3 {Path(__file__)} --output-dir {out_root} --target {args.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

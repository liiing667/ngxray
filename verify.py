#!/usr/bin/env python3
"""
Verify scanner rules by exercising test configs against an ASAN-built nginx.

For each rule's test configs, starts nginx with the snippet wrapped in a
minimal http/server shell, sends a trigger request with '+'-filled URI,
and checks whether ASAN reports a heap-buffer-overflow.

  vulnerable configs → ASAN must fire  (confirms real vulnerability)
  safe configs       → ASAN must not fire (confirms no false positive)

Usage:
    python3 verify.py                          # auto-detect ASAN nginx
    python3 verify.py --nginx /path/to/nginx   # explicit binary
"""

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
RULES_DIR = str(BASE / "rules")
PORT = 19444
TRIGGER_PATH_LEN = 500


def find_nginx():
    """Look for an ASAN-built nginx in common locations."""
    candidates = [
        BASE.parent / "nginx-1.30.0-asan" / "objs" / "nginx",
        BASE / "nginx" / "objs" / "nginx",
        Path("/usr/local/nginx-asan/sbin/nginx"),
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None


def port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def wrap_snippet(snippet, port):
    """Wrap a test config snippet in a runnable nginx config."""
    preamble = (
        f"daemon off;\nmaster_process off;\nworker_processes 1;\n"
        f"error_log stderr;\npid /tmp/_nrs_verify.pid;\n"
        f"events {{ worker_connections 32; }}\n"
    )
    fallback = f'    location / {{ return 200 "ok"; }}\n'

    has_http_block = bool(re.search(r'\bhttp\s*\{', snippet))

    if "events" in snippet and has_http_block:
        return snippet.replace("listen 80", f"listen {port}")

    if re.search(r'\bserver\s*\{', snippet) and not has_http_block:
        patched = re.sub(
            r'(server\s*\{)',
            rf'\1\n    listen {port};',
            snippet, count=1,
        )
        has_catchall = bool(re.search(r'location\s+/\s*\{', snippet))
        if not has_catchall:
            # Insert fallback before the closing } of the server block
            last_brace = patched.rfind("}")
            patched = patched[:last_brace] + fallback + patched[last_brace:]
        return preamble + f"http {{\n  access_log off;\n{patched}\n}}\n"

    # Bare directives (location blocks without server wrapper)
    return (
        preamble +
        f"http {{\n  access_log off;\n"
        f"  server {{\n    listen {port};\n    {snippet}\n{fallback}  }}\n}}\n"
    )


def extract_trigger_prefix(snippet):
    """
    Extract a usable path prefix from location or rewrite directives.
    Strips regex metacharacters to produce a literal prefix that will
    match the location and rewrite patterns.
    """
    # Try location directive first
    m = re.search(r'location\s+~\*?\s*\^?(/[^\s({]*)', snippet)
    if m:
        prefix = re.sub(r'[\\()\[\].*+?$^{}|]', '', m.group(1))
        if prefix and prefix != "/":
            if not prefix.endswith('/'):
                prefix += '/'
            return prefix

    # Try rewrite regex — extract literal prefix
    m = re.search(r'rewrite\s+\^?(/[^\s(]*)', snippet)
    if m:
        prefix = re.sub(r'[\\()\[\].*+?$^{}|]', '', m.group(1))
        if prefix and prefix != "/":
            if not prefix.endswith('/'):
                prefix += '/'
            return prefix

    return "/"


def make_trigger_urls(snippet, port):
    """
    Build trigger URLs. The escapable char depends on which escape mode fires:
      - is_args (?) → '+' expands to %2B under NGX_ESCAPE_ARGS
      - quote (redirect/permanent) → '%' (sent as %25) expands under NGX_ESCAPE_URI
    We send both to cover all cases.
    """
    prefix = extract_trigger_prefix(snippet)
    return [
        f"http://127.0.0.1:{port}{prefix}{'+' * TRIGGER_PATH_LEN}",
        f"http://127.0.0.1:{port}{prefix}{'%25' * TRIGGER_PATH_LEN}",
    ]


def run_one(nginx_bin, snippet, port, expect_crash):
    """
    Run nginx with snippet, send trigger request, check ASAN output.
    Returns (passed: bool, detail: str).
    """
    tmpdir = tempfile.mkdtemp(prefix="_nrs_verify_")
    conf_path = os.path.join(tmpdir, "nginx.conf")

    config = wrap_snippet(snippet, port)
    if f"listen {port}" not in config and "listen " not in config:
        config = config.replace("server {", f"server {{\n    listen {port};", 1)

    # Create logs dir nginx expects
    os.makedirs(os.path.join(tmpdir, "logs"), exist_ok=True)

    with open(conf_path, "w") as f:
        f.write(config)

    # Test config syntax first
    test = subprocess.run(
        [nginx_bin, "-t", "-c", conf_path, "-p", tmpdir],
        capture_output=True, text=True, timeout=5,
    )
    if test.returncode != 0:
        detail = f"config parse failed: {test.stderr.strip()[:200]}"
        _cleanup(tmpdir)
        return (False, detail)

    # Start nginx
    proc = subprocess.Popen(
        [nginx_bin, "-c", conf_path, "-p", tmpdir],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

    try:
        # Wait for it to listen
        for _ in range(20):
            time.sleep(0.1)
            if not port_free(port):
                break
            if proc.poll() is not None:
                break

        if proc.poll() is not None:
            stderr = proc.stderr.read().decode(errors="replace")
            if "AddressSanitizer" in stderr and expect_crash:
                _cleanup(tmpdir)
                return (True, "ASAN fired during startup (config-time)")
            detail = f"nginx exited early: {stderr.strip()[:200]}"
            _cleanup(tmpdir)
            return (False, detail)

        if port_free(port):
            proc.kill()
            proc.wait()
            _cleanup(tmpdir)
            return (False, "nginx did not start listening")

        # Send trigger requests (both + and %25 to cover is_args and quote)
        for url in make_trigger_urls(snippet, port):
            if proc.poll() is not None:
                break
            try:
                subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", url],
                    capture_output=True, text=True, timeout=5,
                )
            except subprocess.TimeoutExpired:
                pass
            time.sleep(0.2)

    finally:
        # Stop nginx
        if proc.poll() is None:
            proc.send_signal(signal.SIGQUIT)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    stderr = proc.stderr.read().decode(errors="replace")
    crashed = "AddressSanitizer" in stderr or "heap-buffer-overflow" in stderr

    if expect_crash and crashed:
        return (True, "ASAN fired — confirmed vulnerable")
    if expect_crash and not crashed:
        return (False, f"expected ASAN crash but nginx exited cleanly (rc={proc.returncode})")
    if not expect_crash and crashed:
        return (False, "ASAN fired on safe config — false negative in rule")
    # not expect_crash and not crashed
    _cleanup(tmpdir)
    return (True, "clean — confirmed safe")


def _cleanup(tmpdir):
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


def load_rules(rules_dir=RULES_DIR):
    rules = []
    for f in sorted(Path(rules_dir).glob("*.json")):
        with open(f) as fh:
            rules.append(json.load(fh))
    return rules


def main():
    ap = argparse.ArgumentParser(description="Verify scanner rules with ASAN nginx")
    ap.add_argument("--nginx", default=None, help="path to ASAN-built nginx binary")
    ap.add_argument("--port", type=int, default=PORT, help=f"port to use (default: {PORT})")
    ap.add_argument("--rules", default=RULES_DIR, help="rules directory")
    ap.add_argument("--rule", default=None, help="test only this rule ID")
    args = ap.parse_args()

    nginx_bin = args.nginx or find_nginx()
    if not nginx_bin or not os.path.exists(nginx_bin):
        print("ASAN nginx binary not found. Use --nginx /path/to/nginx", file=sys.stderr)
        sys.exit(1)

    if not port_free(args.port):
        print(f"port {args.port} is in use", file=sys.stderr)
        sys.exit(1)

    rules = load_rules(args.rules)
    passed = failed = skipped = 0

    for rule in rules:
        tests = rule.get("tests")
        if not tests:
            continue
        if args.rule and rule["id"] != args.rule:
            continue

        rule_id = rule["id"]
        cve = rule.get("cve", "")
        label = f"{rule_id} ({cve})" if cve else rule_id

        print(f"\n{'='*60}")
        print(f"Rule: {label}")
        print(f"{'='*60}")

        for i, snippet in enumerate(tests.get("vulnerable", [])):
            short = snippet[:80].replace("\n", " ")
            ok, detail = run_one(nginx_bin, snippet, args.port, expect_crash=True)
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] vulnerable[{i}]: {detail}")
            if not ok:
                print(f"    config: {short}")
            if ok:
                passed += 1
            else:
                failed += 1

        for i, snippet in enumerate(tests.get("safe", [])):
            short = snippet[:80].replace("\n", " ")
            ok, detail = run_one(nginx_bin, snippet, args.port, expect_crash=False)
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] safe[{i}]: {detail}")
            if not ok:
                print(f"    config: {short}")
            if ok:
                passed += 1
            else:
                failed += 1

    print(f"\n{'='*60}")
    print(f"{passed} passed, {failed} failed")
    print(f"{'='*60}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

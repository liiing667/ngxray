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
import signal
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path

BASE = Path(__file__).resolve().parent
PARSER = str(BASE / "build" / "nginx_conf_parse")
RULES_DIR = str(BASE / "rules")

PHASE_BOUNDARY_DIRECTIVES = frozenset({
    "http", "stream", "mail", "events", "server", "upstream",
    "location", "limit_except", "map", "geo", "split_clients",
    "types",
})

# ── Scan outcome model ─────────────────────────────────────────────────
#
# Every scan ends in exactly one status, and the status, the printed
# evidence and the process exit code always agree (fail closed):
#
#   clean         — every input parsed and every rule evaluated, no findings
#   findings      — evaluation completed, vulnerabilities were found
#   indeterminate — some input/rule could not be evaluated; the "no
#                   finding" verdict cannot be trusted for those inputs
#   canceled      — the scan (or a parser subprocess) was cut short;
#       both        results are partial by definition
#
# Only EXIT_CLEAN is zero.  Downstream automation must treat any
# non-zero exit as "not proven safe".

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_INDETERMINATE = 2
EXIT_CANCELED = 3


class RuleError(Exception):
    """A rule file is invalid; verdicts from it cannot be trusted."""


class EvaluationError(Exception):
    """Evaluation could not reach a trustworthy conclusion."""


# Rule schema.  Unknown keys are rejected at load time: silently ignoring
# a misspelled key would change the meaning of a rule (fail open).

RULE_KEYS = frozenset({
    "id", "cve", "severity", "message", "affected", "fixed", "ref",
    "explanation", "lab_keywords", "ordered", "chainable", "collect",
    "match", "conditions", "manual_review", "tests",
})

PATTERN_KEYS = frozenset({
    "directive", "directive_any_of", "args", "max_args",
    "overlapping_refs", "any_arg", "or", "scope",
})

OR_BRANCH_KEYS = frozenset({"args", "any_arg_from", "any_of"})

CONDITION_KEYS = frozenset({
    "contains", "regex", "not_regex", "any_of", "extract", "min_unique",
    "contains_collected", "capture_before_collected",
})

COLLECT_KEYS = frozenset({"directive", "child_regex", "extract"})

SCOPES = frozenset({"siblings", "subtree", "full_subtree"})


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
    conditions: list[str] = field(default_factory=list)
    manual_review: str = ""
    lab_keywords_matched: list[str] = field(default_factory=list)


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

PCRE_GROUPS = str(BASE / "build" / "pcre_groups")


def _get_group_ancestors(regex):
    """Get the capture group nesting map using PCRE2 via the pcre_groups helper.

    Returns a dict mapping each capturing group number to the set of all
    ancestor group numbers that contain it.

    Raises EvaluationError whenever the helper cannot produce a
    trustworthy answer (missing binary, timeout, rejected pattern, …).
    Returning an empty map here would silently disable the overlap check
    and report vulnerable configs as clean (fail open).
    """
    try:
        r = subprocess.run([PCRE_GROUPS, regex],
                           capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        raise EvaluationError(f"pcre_groups helper unavailable: {e}")

    if r.returncode != 0:
        raise EvaluationError(
            f"pcre_groups exited with status {r.returncode}")

    try:
        rec = json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        raise EvaluationError("pcre_groups returned invalid output")

    if "error" in rec:
        raise EvaluationError(f"pcre_groups rejected regex: {rec['error']}")

    parent_map = rec.get("parent", {})
    ancestors = {}
    for gid_str, pid in parent_map.items():
        gid = int(gid_str)
        anc = set()
        cur = pid
        while cur != 0:
            anc.add(cur)
            cur = parent_map.get(str(cur), 0)
        ancestors[gid] = anc

    return ancestors


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

    out_uri = replacement.split('?')[0]
    if out_uri and not re.search(r'\$[0-9a-zA-Z_]', out_uri):
        try:
            return re.search(args_b[0], out_uri) is not None
        except re.error:
            # Python's re cannot parse every PCRE pattern nginx accepts.
            # An unusable regex check is inconclusive, not negative.
            return True

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
    refs = set(int(m.group(1)) for m in re.finditer(r'\$([1-9])', replacement))
    if len(refs) < 2:
        return False

    ancestors = _get_group_ancestors(regex)

    for a in refs:
        for b in refs:
            if a >= b:
                continue
            if a not in ancestors or b not in ancestors:
                continue
            if a in ancestors[b] or b in ancestors[a]:
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

    Unknown condition keys raise EvaluationError: silently ignoring a
    (possibly misspelled) key would weaken the condition and let a rule
    match configs it was never meant to match (fail open).
    """
    if isinstance(cond, str):
        return value == cond

    if not isinstance(cond, dict):
        raise EvaluationError(f"condition must be a string or object, "
                              f"got {type(cond).__name__}")

    extract_pattern = cond.get("extract")
    min_unique = cond.get("min_unique")

    for key, expected in cond.items():
        if key not in CONDITION_KEYS:
            raise EvaluationError(f"unknown condition key: {key!r}")
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


def check_lab_keywords(filepath, keywords):
    lower = os.path.basename(filepath).lower()
    return [kw for kw in keywords if kw.lower() in lower]


def make_finding(rule, primary, matched, filepath):
    detail_parts = []
    for m in matched:
        args_str = " ".join(m.get("args", []))
        detail_parts.append(f"{m['directive']} {args_str}")

    lab_matched = check_lab_keywords(filepath, rule.get("lab_keywords", []))

    return Finding(
        rule=rule["id"],
        severity=rule["severity"],
        file=filepath,
        line=primary.get("line", 0),
        message=rule["message"],
        cve=rule.get("cve", ""),
        details="\n".join(detail_parts),
        conditions=list(rule.get("conditions", [])),
        manual_review=rule.get("manual_review", ""),
        lab_keywords_matched=lab_matched,
    )


# ── Rule loading ───────────────────────────────────────────────────────

def _validate_condition_spec(cond, where):
    """Reject malformed conditions at load time (fail closed)."""
    if isinstance(cond, str):
        return
    if not isinstance(cond, dict):
        raise RuleError(f"{where}: condition must be a string or object")
    for key, val in cond.items():
        if key not in CONDITION_KEYS:
            raise RuleError(f"{where}: unknown condition key {key!r}")
        if key in ("regex", "not_regex", "extract"):
            if not isinstance(val, str):
                raise RuleError(f"{where}: {key!r} must be a string")
            try:
                re.compile(val)
            except re.error as e:
                raise RuleError(f"{where}: invalid {key} pattern: {e}")
        elif key == "contains":
            if not isinstance(val, str):
                raise RuleError(f"{where}: 'contains' must be a string")
        elif key == "any_of":
            if (not isinstance(val, list)
                    or not all(isinstance(v, str) for v in val)):
                raise RuleError(f"{where}: 'any_of' must be a list of strings")
        elif key == "min_unique":
            if not isinstance(val, int):
                raise RuleError(f"{where}: 'min_unique' must be an integer")
        elif key in ("contains_collected", "capture_before_collected"):
            if not isinstance(val, bool):
                raise RuleError(f"{where}: {key!r} must be a boolean")


def _validate_args_spec(args, where):
    if not isinstance(args, dict):
        raise RuleError(f"{where}: 'args' must be an object")
    for idx_str, cond in args.items():
        try:
            idx = int(idx_str)
        except (TypeError, ValueError):
            raise RuleError(f"{where}: arg index {idx_str!r} is not an integer")
        if idx < 0:
            raise RuleError(f"{where}: arg index {idx_str!r} is negative")
        _validate_condition_spec(cond, f"{where} args[{idx_str!r}]")


def _validate_pattern(pat, where):
    if not isinstance(pat, dict):
        raise RuleError(f"{where}: match pattern must be an object")
    unknown = set(pat) - PATTERN_KEYS
    if unknown:
        raise RuleError(f"{where}: unknown pattern keys: {sorted(unknown)}")
    if "directive" not in pat and "directive_any_of" not in pat:
        raise RuleError(
            f"{where}: pattern needs 'directive' or 'directive_any_of'")
    if "directive" in pat and not isinstance(pat["directive"], str):
        raise RuleError(f"{where}: 'directive' must be a string")
    if "directive_any_of" in pat:
        names = pat["directive_any_of"]
        if (not isinstance(names, list)
                or not all(isinstance(n, str) for n in names)):
            raise RuleError(
                f"{where}: 'directive_any_of' must be a list of strings")
    scope = pat.get("scope", "siblings")
    if scope not in SCOPES:
        raise RuleError(f"{where}: unknown scope {scope!r}")
    if "args" in pat:
        _validate_args_spec(pat["args"], where)
    if "max_args" in pat and not isinstance(pat["max_args"], int):
        raise RuleError(f"{where}: 'max_args' must be an integer")
    if "overlapping_refs" in pat and not isinstance(pat["overlapping_refs"], bool):
        raise RuleError(f"{where}: 'overlapping_refs' must be a boolean")
    if "any_arg" in pat:
        _validate_condition_spec(pat["any_arg"], f"{where} 'any_arg'")
    for branch in pat.get("or", []):
        if not isinstance(branch, dict):
            raise RuleError(f"{where}: 'or' branches must be objects")
        unknown = set(branch) - OR_BRANCH_KEYS
        if unknown:
            raise RuleError(
                f"{where}: unknown 'or' branch keys: {sorted(unknown)}")
        if "args" in branch:
            _validate_args_spec(branch["args"], f"{where} 'or' branch")
        if "any_arg_from" in branch and not isinstance(branch["any_arg_from"], int):
            raise RuleError(f"{where}: 'any_arg_from' must be an integer")
        if "any_of" in branch:
            any_of = branch["any_of"]
            if (not isinstance(any_of, list)
                    or not all(isinstance(v, str) for v in any_of)):
                raise RuleError(
                    f"{where}: branch 'any_of' must be a list of strings")


def validate_rule(rule, source):
    """Validate a rule's structure; raise RuleError if it cannot be trusted."""
    where = source
    if not isinstance(rule, dict):
        raise RuleError(f"{where}: rule must be a JSON object")
    unknown = set(rule) - RULE_KEYS
    if unknown:
        raise RuleError(f"{where}: unknown rule keys: {sorted(unknown)}")
    for required in ("id", "severity", "message"):
        if not isinstance(rule.get(required), str) or not rule.get(required):
            raise RuleError(
                f"{where}: missing or invalid required field {required!r}")
    where = f"{source} (rule {rule['id']})"
    match = rule.get("match")
    if not isinstance(match, list) or not match:
        raise RuleError(f"{where}: 'match' must be a non-empty list")
    for pat in match:
        _validate_pattern(pat, where)
    if rule.get("chainable") and len(match) < 2:
        raise RuleError(f"{where}: 'chainable' needs at least 2 patterns")
    if "collect" in rule:
        collect = rule["collect"]
        if not isinstance(collect, dict):
            raise RuleError(f"{where}: 'collect' must be an object")
        unknown = set(collect) - COLLECT_KEYS
        if unknown:
            raise RuleError(f"{where}: unknown collect keys: {sorted(unknown)}")
        if not isinstance(collect.get("directive"), str):
            raise RuleError(f"{where}: 'collect' needs a 'directive' string")
        child_regex = collect.get("child_regex")
        if child_regex is not None:
            if not isinstance(child_regex, str):
                raise RuleError(f"{where}: 'child_regex' must be a string")
            try:
                re.compile(child_regex)
            except re.error as e:
                raise RuleError(f"{where}: invalid 'child_regex': {e}")
        if "extract" in collect and not isinstance(collect["extract"], str):
            raise RuleError(f"{where}: 'extract' must be a string")


def load_rules(rules_dir=RULES_DIR):
    rules = []
    for f in sorted(Path(rules_dir).glob("*.json")):
        try:
            with open(f) as fh:
                rule = json.load(fh)
        except OSError as e:
            raise RuleError(f"{f}: cannot read rule: {e}")
        except json.JSONDecodeError as e:
            raise RuleError(f"{f}: invalid JSON: {e}")
        validate_rule(rule, str(f))
        rules.append(rule)
    return rules


# ── Config parsing ─────────────────────────────────────────────────────

def parse_file_result(filepath):
    """Parse one config file with the nginx tokenizer.

    Returns (ast, error).  On success error is None.  Otherwise error is
    the string "canceled" if the parser had to be killed (timeout), or a
    human-readable description of the failure.  Callers must treat any
    error as "cannot determine", never as "clean".
    """
    try:
        r = subprocess.run([PARSER, filepath],
                           capture_output=True, text=True, errors="replace",
                           timeout=10)
    except subprocess.TimeoutExpired:
        return None, "canceled"
    except (FileNotFoundError, OSError) as e:
        return None, f"parser unavailable: {e}"
    if r.returncode != 0:
        return None, f"parse failed (parser exited with status {r.returncode})"
    try:
        return json.loads(r.stdout), None
    except json.JSONDecodeError:
        return None, "parse failed (parser returned invalid JSON)"


def parse_file(filepath):
    ast, _ = parse_file_result(filepath)
    return ast


def validate_ast(nodes, what="config"):
    """Ensure a parsed AST has the structure the evaluator relies on.

    Pre-parsed JSONL input is attacker-controlled; a malformed node must
    make the file indeterminate instead of crashing the evaluator or,
    worse, being silently skipped.
    """
    if not isinstance(nodes, list):
        raise EvaluationError(f"{what}: top-level AST is not a list")
    for n in nodes:
        if not isinstance(n, dict) or not isinstance(n.get("directive"), str):
            raise EvaluationError(
                f"{what}: malformed AST node (missing 'directive')")
        args = n.get("args", [])
        if (not isinstance(args, list)
                or not all(isinstance(a, str) for a in args)):
            raise EvaluationError(f"{what}: malformed 'args' in AST node")
        line = n.get("line", 0)
        if not isinstance(line, int):
            raise EvaluationError(f"{what}: malformed 'line' in AST node")
        blk = n.get("block", [])
        if blk:
            validate_ast(blk, what)


# ── Scan state ─────────────────────────────────────────────────────────

class ScanState:
    """Accumulates findings, errors and cancellation across all inputs."""

    def __init__(self):
        self.findings = []
        self.scanned = 0
        self.failed = 0
        self.errors = []
        self.canceled = False

    def error(self, msg):
        self.failed += 1
        self.errors.append(msg)

    @property
    def status(self):
        if self.canceled:
            return "canceled"
        if self.failed:
            return "indeterminate"
        if self.findings:
            return "findings"
        return "clean"

    @property
    def exit_code(self):
        return {
            "clean": EXIT_CLEAN,
            "findings": EXIT_FINDINGS,
            "indeterminate": EXIT_INDETERMINATE,
            "canceled": EXIT_CANCELED,
        }[self.status]


def scan_one(state, rules, ast, filepath):
    """Evaluate all rules against one parsed config, fail closed."""
    try:
        validate_ast(ast, filepath)
    except EvaluationError as e:
        state.error(str(e))
        return
    state.scanned += 1
    for rule in rules:
        try:
            state.findings.extend(eval_rule(rule, ast, filepath))
        except EvaluationError as e:
            state.error(f"{filepath}: rule {rule.get('id', '?')}: {e}")
        except Exception as e:
            # A bug in the evaluator must not silently skip a rule.
            state.error(f"{filepath}: rule {rule.get('id', '?')}: "
                        f"internal evaluation error: {e}")


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
            try:
                findings = eval_rule(rule, ast, "<test>")
            except EvaluationError as e:
                print(f"  FAIL [{rule_id}] evaluation error: {e}")
                failed += 1
                continue
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
            try:
                findings = eval_rule(rule, ast, "<test>")
            except EvaluationError as e:
                print(f"  FAIL [{rule_id}] evaluation error: {e}")
                failed += 1
                continue
            if not findings:
                passed += 1
            else:
                print(f"  FAIL [{rule_id}] expected no finding but got:")
                print(f"    {snippet[:100]}")
                print(f"    finding: {findings[0].message}")
                failed += 1

    return passed, failed


# ── Main ───────────────────────────────────────────────────────────────

def _raise_canceled(signum, frame):
    """Convert SIGTERM into KeyboardInterrupt so the scan can report
    cancellation and exit with EXIT_CANCELED instead of dying silently."""
    raise KeyboardInterrupt


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
        try:
            passed, failed = run_tests(args.rules)
        except RuleError as e:
            print(f"rule error: {e}", file=sys.stderr)
            sys.exit(1)
        total = passed + failed
        print(f"{passed}/{total} tests passed")
        sys.exit(1 if failed else 0)

    try:
        rules = load_rules(args.rules)
    except RuleError as e:
        print(f"rule error: {e}", file=sys.stderr)
        sys.exit(EXIT_INDETERMINATE)
    if not rules:
        print(f"no rules found in {args.rules} — cannot scan",
              file=sys.stderr)
        sys.exit(EXIT_INDETERMINATE)

    state = ScanState()

    signal.signal(signal.SIGTERM, _raise_canceled)

    def scan_path(path):
        ast, err = parse_file_result(path)
        if err == "canceled":
            state.canceled = True
            state.error(f"{path}: parser timed out and was killed")
        elif ast is None:
            state.error(f"{path}: {err}")
        else:
            scan_one(state, rules, ast, path)

    def handle_record(rec):
        if not isinstance(rec, dict):
            state.error("jsonl: record is not a JSON object")
            return
        if rec.get("error"):
            state.error(f"{rec.get('file', '?')}: parse failed")
            return
        if "config" not in rec:
            state.error(f"{rec.get('file', '?')}: "
                        f"jsonl record missing 'config'")
            return
        scan_one(state, rules, rec["config"], rec.get("file", "?"))

    try:
        if args.jsonl:
            if args.input == "-":
                stream = sys.stdin
            else:
                try:
                    stream = open(args.input)
                except OSError as e:
                    print(f"cannot open {args.input}: {e}", file=sys.stderr)
                    sys.exit(EXIT_INDETERMINATE)
            buf = []
            for line in stream:
                stripped = line.rstrip("\n")
                if not buf:
                    if not stripped.startswith("{"):
                        continue
                    # Single-line records (e.g. error records)
                    if stripped.endswith("}"):
                        try:
                            rec = json.loads(stripped)
                        except json.JSONDecodeError:
                            state.error("jsonl: undecodable record")
                            continue
                        handle_record(rec)
                    else:
                        buf.append(line)
                    continue
                buf.append(line)
                if stripped == "}":
                    try:
                        rec = json.loads("".join(buf))
                    except json.JSONDecodeError:
                        state.error("jsonl: undecodable record")
                        buf = []
                        continue
                    buf = []
                    handle_record(rec)
            if buf:
                # Producer was cut off mid-record: results are partial.
                state.canceled = True
                state.error("jsonl: truncated final record "
                            "(producer canceled?)")

        elif args.input == "-" and not args.jsonl:
            for line in sys.stdin:
                path = line.strip()
                if not path:
                    continue
                scan_path(path)

        elif os.path.isdir(args.input):
            for root, _, files in os.walk(args.input):
                for f in sorted(files):
                    if not f.endswith(".conf"):
                        continue
                    scan_path(os.path.join(root, f))

        else:
            scan_path(args.input)

    except KeyboardInterrupt:
        state.canceled = True
        print("scan canceled — results are partial", file=sys.stderr)
    except Exception as e:
        # Any unexpected failure still fails closed.
        state.error(f"internal error: {e}")

    if args.json:
        json.dump([asdict(f) for f in state.findings], sys.stdout, indent=2)
        print()
    else:
        if state.findings:
            for f in state.findings:
                cve = f" ({f.cve})" if f.cve else ""
                print(f"[{f.severity}] {f.rule}{cve}")
                print(f"  {f.file}:{f.line}")
                print(f"  {f.message}")
                if f.details:
                    for dl in f.details.split("\n"):
                        print(f"    {dl}")
                if f.conditions:
                    print("    conditions required:")
                    for cond in f.conditions:
                        print(f"      - {cond}")
                if f.manual_review:
                    print(f"    manual review: {f.manual_review}")
                if f.lab_keywords_matched:
                    kws = ", ".join(f.lab_keywords_matched)
                    print(f"    lab/poc indicator: matched keywords: {kws}")
                print()
        elif not state.failed and not state.canceled:
            print("No vulnerabilities found.", file=sys.stderr)

    for e in state.errors:
        print(f"error: {e}", file=sys.stderr)
    print(f"status: {state.status}", file=sys.stderr)
    print(f"{len(state.findings)} finding(s) in "
          f"{state.scanned} config(s) ({state.failed} failed)",
          file=sys.stderr)
    sys.exit(state.exit_code)


if __name__ == "__main__":
    main()

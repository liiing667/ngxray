# ngxray

Static vulnerability scanner for nginx configurations. Parses configs with nginx's own tokenizer and matches against declarative JSON rules to detect known CVEs in rewrite/script engine directive patterns.

## Quick start

```bash
cd ngxray
git submodule update --init
make
python3 scan.py /etc/nginx/nginx.conf
```

## What it detects

Rules are defined as JSON files in `rules/`. The scanner ships with:

| Rule | CVE | Pattern |
|------|-----|---------|
| `rewrite-is-args` | [CVE-2026-42945](https://my.f5.com/manage/s/article/K000160932) | `rewrite … /path?args` + `set $var $1` |
| `rewrite-is-args-if` | [CVE-2026-42945](https://my.f5.com/manage/s/article/K000160932) | `rewrite … /path?args` + `if (… $1 …)` |
| `nested-capture-redirect` | [CVE-2026-9256](https://my.f5.com/manage/s/article/K000161377) | `rewrite ^/((…))$ … redirect` with overlapping `$N` |

### CVE-2026-42945 — `is_args` stale flag overflow

**Affected:** NGINX 0.6.27 – 1.30.0, NGINX Plus R32 – R36. **Fixed:** 1.31.0 / 1.30.1.

A `rewrite` replacement containing `?` sets `e->is_args=1` in the script engine. This flag persists into subsequent `set` or `if` directives, causing the copy pass to URI-escape capture data (3x expansion) into a buffer sized for raw bytes.

```nginx
location ~ ^/api/(.*)$ {
    rewrite ^/api/(.*)$ /internal?migrated=true;
    set $original_endpoint $1;    # $1 evaluated with stale is_args=1
}
```

### CVE-2026-9256 — nested capture fast-path overflow

**Affected:** through NGINX 1.31.0. **Fixed:** 1.31.1 / 1.30.2.

Nested capture groups cause the fast-path escape budget to undercount — the same URI bytes are escaped once per overlapping `$N` reference.

```nginx
rewrite ^/((.*))$ http://backend/$1$2 redirect;
```

## Usage

```bash
# Single file
python3 scan.py /etc/nginx/nginx.conf

# Directory (recursive, all *.conf files)
python3 scan.py /etc/nginx/

# Filenames from stdin
find /etc/nginx -name '*.conf' | python3 scan.py -

# Pre-parsed JSONL (faster for large batches)
find /etc/nginx -name '*.conf' | ./build/nginx_conf_parse - | python3 scan.py --jsonl -

# JSON output
python3 scan.py --json /etc/nginx/nginx.conf

# Custom rules directory
python3 scan.py --rules ./my-rules/ /etc/nginx/nginx.conf
```

## Suppressing rules

Findings can be suppressed per rule ID — exact matches only, never globs, so
suppressing one rule can never hide findings from a different rule:

```bash
# Suppress one or more rules by ID (repeatable, comma-separated accepted)
python3 scan.py --ignore rewrite-is-args-chain /etc/nginx/

# Suppress via a file: one rule ID per line, '#' comments allowed
python3 scan.py --ignore-file ./ngxray.ignore /etc/nginx/
```

Unknown rule IDs in an ignore list produce a warning on stderr.

## Exit codes

The exit code reflects the **highest** severity among all remaining
findings — computed as a maximum, never from the last rule evaluated, so a
later low-severity rule can never downgrade a high-severity result:

| Code | Meaning |
|------|---------|
| 0 | no findings (after ignores) |
| 1 | highest finding severity is INFO/LOW |
| 2 | highest finding severity is MEDIUM |
| 3 | highest finding severity is HIGH |
| 4 | highest finding severity is CRITICAL |
| 5 | tool error (unparseable config, unreadable rules/ignore file) |

`--test` keeps its own convention: 0 when all embedded rule tests pass, 1
otherwise.

## Corpus Collection

The `corpus_tools/` package can collect public nginx configuration material
from GitHub Code Search and extract nginx snippets from wrapper formats.

```bash
python3 corpus_tools/collect_github_nginx_corpus.py \
  --output-dir corpus_out/nginx-rift \
  --query-file corpus_tools/queries/nginx-rift.txt

python3 corpus_tools/extract_nginx_configs.py \
  --input-dir corpus_out/nginx-rift/raw \
  --output-dir corpus_out/nginx-rift/extracted

python3 scan.py corpus_out/nginx-rift/extracted
```

See `corpus_tools/README.md` and `corpus_tools/docs/` for the full workflow and
the documented Rift-focused collection method.

## Adding new rules

Drop a JSON file in `rules/`. The engine loads all `*.json` files from the rules directory at startup.

### Rule schema

```json
{
  "id": "rule-name",
  "cve": "CVE-YYYY-NNNNN",
  "severity": "CRITICAL",
  "message": "short description shown in output",
  "affected": "nginx version range",
  "fixed": "fixed versions",
  "ref": "https://link-to-advisory",

  "match": [ ... ],

  "tests": {
    "vulnerable": ["server { ... }"],
    "safe": ["server { ... }"]
  }
}
```

Each rule can include `tests` with `vulnerable` (must trigger) and `safe` (must not trigger) config snippets. Run `python3 scan.py --test` to validate all rules.

### Match patterns

`match` is a list of directive conditions. If there's one condition, the engine searches the entire config tree for any matching directive. If there are multiple, all conditions must match sibling directives in the same block.

Each condition:

```json
{
  "directive": "rewrite",

  "args": {
    "0": { "contains": "?" },
    "1": { "regex": "\\$[1-9]" }
  },

  "any_arg": { "regex": "\\$[1-9]" },

  "or": [
    { "args": { "1": { "contains": "?" } } },
    { "any_arg_from": 2, "any_of": ["redirect", "permanent"] }
  ]
}
```

- **`args`** — keyed by position (as string). Each value is a condition object.
- **`max_args`** — reject if the directive has more than N args.
- **`overlapping_refs`** — verify that `$N` references in `args[1]` correspond to capture groups in `args[0]` that physically contain each other.
- **`any_arg`** — condition must match at least one arg at any position.
- **`or`** — at least one branch must match. Branches can check `args` or `any_arg_from` + `any_of`.

### Condition objects

| Key | Type | Matches when |
|-----|------|-------------|
| `contains` | string | Arg contains the substring |
| `regex` | string | Arg matches the regex |
| `not_regex` | string | Arg does NOT match the regex |
| `any_of` | [string] | Arg equals one of the values |
| `extract` | string | Regex with a capture group — extracts all matches for counting |
| `min_unique` | int | (used with `extract`) At least N distinct matches found |

`extract` + `min_unique` is the general mechanism for counting patterns in an arg. For example, to require at least 2 distinct capture references (`$1`–`$9`):

```json
{ "extract": "\\$([1-9])", "min_unique": 2 }
```

### Example: adding a new CVE

```json
{
  "id": "proxy-buffer-overflow",
  "cve": "CVE-2099-99999",
  "severity": "CRITICAL",
  "message": "proxy_pass with oversized buffer — heap overflow",
  "ref": "https://example.com/advisory",
  "match": [
    {
      "directive": "proxy_pass",
      "args": { "0": { "regex": "https?://" } }
    },
    {
      "directive": "proxy_buffer_size",
      "args": { "0": { "regex": "^(6[5-9]|[7-9]\\d|\\d{3,})k$" } }
    }
  ],
  "tests": {
    "vulnerable": [
      "server { location / { proxy_pass http://backend; proxy_buffer_size 128k; } }"
    ],
    "safe": [
      "server { location / { proxy_pass http://backend; proxy_buffer_size 8k; } }"
    ]
  }
}
```

## How it works

### Parser

The `parser/` directory contains a standalone C program that uses nginx's own tokenizer (`ngx_conf_read_token` and `ngx_conf_parse` from `src/core/ngx_conf_file.c`) to parse config files into a JSON AST. This is the same lexer nginx uses at startup — no reimplementation.

The key modification: `ngx_conf_handler()` (which dispatches directives to compiled-in modules) is replaced with `conf_handler()`, which records every directive into a tree regardless of name. This lets the parser handle any valid config without the module system. The modification is applied as a patch at build time — no nginx source files are copied into this repo.

The remaining nginx source files (pool allocator, string functions, logging, etc.) are compiled directly from the submodule.

### Scanner

`scan.py` loads JSON rules from `rules/`, parses configs via `nginx_conf_parse`, and evaluates each rule against the AST. All detection specifics live in the JSON rule files.

### Evaluation semantics

- **Inheritance** — like nginx itself, a `server`/`location`/`limit_except`
  block with no rewrite-phase directives (`rewrite`, `set`, `if`, `break`,
  `return`) of its own inherits the nearest enclosing level's rewrite-phase
  directives; multi-directive rules are evaluated against these effective
  blocks. Blocks defining their own rewrite-phase directives are evaluated
  as-is. Identical findings surfaced through several inheriting blocks are
  reported once.
- **Rule priority** — rules are evaluated in deterministic order: highest
  severity first, ties broken by rule ID. Findings are reported sorted by
  location, then highest severity first. Conflicts are never resolved by
  evaluation or file order (no last-one-wins): every finding is kept, and
  any aggregate result (counts, exit code) is the maximum severity.

## Building

Requires a C compiler and Python 3. nginx source is included as a git submodule.

```bash
git submodule update --init
make
make test
```

## Mirroring

This repo is mirrored read-only to [github.com/califio/ngxray](https://github.com/califio/ngxray) via Copybara. See [COPYBARA.md](COPYBARA.md).

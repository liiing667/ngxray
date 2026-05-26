# p0poff/storage Review

Source:

- Repository: `p0poff/storage`
- File: `nginx.conf`
- Scanned commit: `bd5a9ebd18c451c8e9b9414f7da65b98ad3067d6`
- Local extracted file in the reference run: `github_nginx_corpus/rift_search/extracted/p0poff__storage__nginx.conf`

## Verdict

`p0poff/storage` is not reachable for original nginx-Rift / CVE-2026-42945 as written.

It is a real deployable Docker application rather than a docs snippet: `Dockerfile` copies `nginx.conf` into `/etc/nginx/conf.d/nginx.conf`, and the README starts the container on port 80. The static detector still flagged four hits because it flattened sibling `if` blocks inside the server rewrite phase.

## Why The Static Hit Is False

The relevant config has four server-level `if ($args ~ ...)` blocks. In every block, the order is:

```nginx
set $w_or_h $N;
rewrite ^(.*).(jpg|png|gif|jpeg)$ ...?;
```

That means the capture-consuming `set` runs before the local rewrite that can set `e->is_args`.

For a successful image rewrite, the replacement ends in a bare `?`, so nginx immediately rewrites the URI and clears request args. All later sibling `if` blocks are gated on `$args`, so they evaluate false and their `set` directives do not run under the stale `is_args` state.

For a non-image URI, the rewrite regex does not match. Later `if` blocks can still run, but the prior rewrite did not execute its replacement/args opcodes, so there is no stale `is_args` state from that rewrite.

## Runtime Check

I validated this with the local vulnerable nginx 1.30.0 ASAN/debug build:

```sh
ASAN_OPTIONS=detect_leaks=0 nginx-1.30.0-asan/objs/nginx \
  -p "$PWD/audit_tmp/p0poff_runtime" \
  -c nginx.conf -t
```

The test wrapper changes only the listen port and stubs `uwsgi_params`; the rewrite logic is the p0poff config. Probe requests used `%`/`+` in the URI and args to satisfy the usual Rift request-side preconditions.

Observed debug behavior:

- `width=A+B&height=C+D`: `set $w`, `set $h`, successful image rewrite, `args: ""`, later `if` blocks false.
- `height=C+D&width=A+B`: first `if` false, second block `set`s before successful rewrite, `args: ""`, later `if` blocks false.
- `width=A+B` and `height=C+D`: single-parameter `set` before successful rewrite, then `args: ""`.
- `notimage.txt?width=A+B&height=C+D`: later `set`s can run, but only after failed image rewrite regexes; no `regex end`/args opcode from a successful prior rewrite.

No AddressSanitizer fault was emitted.

## Scanner Follow-Up

The scanner should treat sibling `if` blocks path-sensitively. A safe
improvement is to avoid carrying ordered matches across branches unless a later
directive is reachable after a successful rewrite in the same branch. The
`scan.py` ordered matcher now compares source order across subtree matches, so
`set $ep $1; rewrite ... ?;` is no longer reported as the original Rift shape.

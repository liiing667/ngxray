# ngxray corpus tools

Utilities for collecting public nginx configuration material and extracting
clean `.conf` snippets from wrappers such as Dockerfiles, shell scripts,
templates, Kubernetes YAML, Helm values, and Markdown docs.

These tools are source-only. They do not include the downloaded GitHub corpus.

## Requirements

- Python 3.10+
- `requests`
- A GitHub token with read-only public code search access

The collector reads `GITHUB_TOKEN` or `GH_TOKEN` from the environment. It can
also load either value from `.env` in the current working directory.

## Collect A Rift-Focused Corpus

From the repository root:

```sh
python3 corpus_tools/collect_github_nginx_corpus.py \
  --output-dir corpus_out/nginx-rift \
  --query-file corpus_tools/queries/nginx-rift.txt \
  --target 20000 \
  --per-page 100 \
  --page-limit 10 \
  --workers 8 \
  --sleep 2.1
```

The run is resumable. Re-running the same command continues from
`corpus_out/nginx-rift/state.json`.

Output layout:

```text
corpus_out/nginx-rift/raw/metadata.json
corpus_out/nginx-rift/raw/*
corpus_out/nginx-rift/candidates.jsonl
corpus_out/nginx-rift/state.json
```

## Extract Configs

```sh
python3 corpus_tools/extract_nginx_configs.py \
  --input-dir corpus_out/nginx-rift/raw \
  --output-dir corpus_out/nginx-rift/extracted
```

The extractor writes normalized `.conf` files plus provenance metadata:

```text
corpus_out/nginx-rift/extracted/*.conf
corpus_out/nginx-rift/extracted/metadata.json
```

## Scan Extracted Configs With ngxray

```sh
python3 scan.py corpus_out/nginx-rift/extracted --json \
  > corpus_out/nginx-rift/findings.json
```

For large runs, build the parser first:

```sh
make
find corpus_out/nginx-rift/extracted -name '*.conf' \
  | ./build/nginx_conf_parse - \
  | python3 scan.py --jsonl - --json \
  > corpus_out/nginx-rift/findings.json
```

## Included Queries

- `queries/nginx-rift.txt`: targeted GitHub Code Search queries for original
  nginx-Rift patterns, especially `rewrite`, `set`, numeric captures, and `?`
  rewrite replacements across raw configs and embedded wrapper formats.

## Docs

- `docs/nginx-rift-collection.md`: exact collection and extraction method used
  for the Rift-focused corpus run.
- `docs/p0poff-storage-review.md`: false-positive case study for a real
  deployable config that is not reachable for original nginx-Rift.

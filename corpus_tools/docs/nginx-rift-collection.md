# GitHub Collection Method

This document records the Rift-focused GitHub corpus collection method. In this
repository, use `corpus_out/nginx-rift/` for generated data:

```text
corpus_out/nginx-rift/
```

## Inputs

- Token: `GITHUB_TOKEN` or `GH_TOKEN` from `.env`; the collector reads it but does not print it.
- Query list: `corpus_tools/queries/nginx-rift.txt`
- Collector: `corpus_tools/collect_github_nginx_corpus.py`
- Extractor: `corpus_tools/extract_nginx_configs.py`

The query list is biased toward original nginx-Rift shapes: `rewrite`, `set`, numeric captures like `$1`, and rewrite replacements containing `?`. It also searches wrapper formats where nginx configs are commonly embedded: Dockerfiles, shell scripts, Markdown, YAML, Helm/Kubernetes files, templates, and deployment directories.

## Raw Fetch

The effective fetch command was:

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

The run is resumable through `corpus_out/nginx-rift/state.json`. GitHub code
search may exhaust the targeted query set before reaching the `20000` target.

The collector:

- Calls the GitHub Code Search API with the authenticated token.
- Downloads raw file contents for accepted search results.
- Scores files for nginx-like syntax before accepting them.
- Stores raw files under `raw/`.
- Stores provenance under `raw/metadata.json`.
- Logs accepted candidates to `candidates.jsonl`.
- Deduplicates by repository/path and content hash.
- Follows wrapper references, for example nginx config paths copied or included by Dockerfiles and scripts.

Final raw totals:

- Raw candidates accepted: `8761`
- Unique repositories: `7061`
- Raw bytes by GitHub file size: `210133824`

## Extraction

Raw files were normalized/extracted with:

```sh
python3 corpus_tools/extract_nginx_configs.py \
  --input-dir corpus_out/nginx-rift/raw \
  --output-dir corpus_out/nginx-rift/extracted
```

The extractor handles:

- Plain nginx configs.
- Jinja2 and ERB templates.
- Shell heredocs and generated config scripts.
- Kubernetes/Helm/YAML embedded config blocks.
- Markdown fenced nginx examples.

The extracted configs and their provenance are in:

```text
corpus_out/nginx-rift/extracted/
corpus_out/nginx-rift/extracted/metadata.json
```

Final extraction total:

- Extracted configs/snippets: `9856`

## Rift Scan With ngxray

The extracted configs can be scanned directly with ngxray:

```sh
python3 scan.py corpus_out/nginx-rift/extracted --json \
  > corpus_out/nginx-rift/findings.json
```

For larger corpora, use the parser pipeline:

```sh
make
find corpus_out/nginx-rift/extracted -name '*.conf' \
  | ./build/nginx_conf_parse - \
  | python3 scan.py --jsonl - --json \
  > corpus_out/nginx-rift/findings.json
```

## Reference Run Totals

The original local run using this query set produced:

- Raw candidates accepted: `8761`
- Unique repositories: `7061`
- Raw bytes by GitHub file size: `210133824`
- Extracted configs/snippets: `9856`
- Targeted Rift detector hits before manual classification: `47`
- Repositories with detector hits: `20`
- Confirmed non-demo deployable Rift configs after review: `0`

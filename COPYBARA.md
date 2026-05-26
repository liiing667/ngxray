# Mirroring to GitHub

This repo is mirrored read-only from internal GitLab to
[github.com/califio/ngxray](https://github.com/califio/ngxray) via
[Copybara](https://github.com/google/copybara). `copy.bara.sky` is the sync
config.

## Install Copybara

See upstream instructions: <https://github.com/google/copybara#getting-started>.
Short version: build from source with Bazel, or use a prebuilt jar:

```bash
# requires JDK 11+ on PATH
java -jar copybara.jar --version
```

A wrapper at `~/bin/copybara` that execs the jar is convenient but must forward
arguments (`exec java -jar ~/bin/copybara.jar "$@"`).

## Run a sync

```bash
copybara migrate copy.bara.sky default
```

First-ever push to an empty destination needs:

```bash
copybara migrate copy.bara.sky default --init-history --force
```

Add `--dry-run` to stage commits locally without pushing. After a dry run,
inspect what would land with:

```bash
GIT_DIR=~/copybara/cache/git_repos/git%40github%2Ecom%3Acalifio%2Fngxray%2Egit \
    git log main
```

## Author mapping

Per-author rewrites live in `copy.bara.sky` under `metadata.map_author`. To add
a new contributor, append their internal email to `authoring.allowed` *and* to
the `map_author` dict — otherwise their commits are squashed under the default
`Calif <eng@calif.io>` identity.

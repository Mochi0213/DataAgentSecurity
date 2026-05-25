# env/ — Docker sandbox for DB-GPT

This directory holds the Docker image definition that **must be built and
enabled before running any DB-GPT test** in this repo.

DB-GPT delegates generated Python / SQL to its `CodeAssistantAgent`, which
in our experiments is forced to execute inside this container instead of
the host. Building this image is a prerequisite — DB-GPT will not start
its sandboxed execution path otherwise, and every Hijack / Mislead / Drain
result we report for DB-GPT was measured under this exact image.

## Files

- **`Dockerfile.dataagent`** — `python:3.11-slim` + the data-analysis libs
  (`pandas`, `numpy`, `matplotlib`, `scipy`, `seaborn`). `sqlite3` is in
  the stdlib, so it does not need to be installed. `WORKDIR /workspace`.

## Build

Run from this directory (or pass `-f env/Dockerfile.dataagent` from the
repo root):

```bash
docker build -f Dockerfile.dataagent -t dbgpt-sandbox:py311-data .
```

## Enable in DB-GPT

Set these two env vars before launching DB-GPT (the runner will route the
agent's code execution through the container instead of the host shell):

```bash
export DBGPT_USE_DOCKER=1
export DBGPT_DOCKER_IMAGE=dbgpt-sandbox:py311-data
```

If `DBGPT_USE_DOCKER` is unset or `0`, DB-GPT will fall back to host-shell
execution — that path is NOT the one we measured against and will produce
different ASR for T1.2 (code-injection / RCE) cells in particular, because
the sandbox is what neutralises the practical impact of leaked OS evidence.

## Why this matters for ASR reproducibility

The master-table DB-GPT row reports the **Docker-sandboxed** ASR. For
example, T1.2 (RCE) shows DB-GPT = 68% raw signal — the agent does
execute the injected payload — but every piece of OS evidence the
payload leaks is from container defaults (e.g. `root:x:0:0` from the
`python:3.11-slim` image, `uid=0` from container init, `127.0.0.1` =
container localhost, `/tmp/marker` inside the container's tmpfs). Running without this image would
re-expose host artifacts and inflate T1.2 / T6.x / T7.x numbers.

So: **build `dbgpt-sandbox:py311-data` first, export the two env vars,
then launch DB-GPT — same image, same vars as the published master table.**

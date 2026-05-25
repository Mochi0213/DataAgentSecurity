#!/usr/bin/env python3
"""DB-GPT attack runner (Docker-sandboxed) for the consolidated DataAgentSecurity_Test repo.

Walks all 350 attack manifests under test_case/{Hijack,Mislead,Drain}/manifests/,
prepares a per-manifest workspace (DB copy + optional INSERT injection_sql +
aux files), drives DB-GPT through the OpenRouter-pinned session driver, and
writes one transcript JSON per manifest into transcripts/<Group>/<Technique>/.

Pre-requisites
--------------
1. Docker daemon up and the sandbox image built:
       docker build -f env/Dockerfile.dataagent -t dbgpt-sandbox:py311-data env/
2. OpenRouter key dropped into env/YOUR_OPENROUTER_KEY.txt
   (the first non-comment, non-blank line of the file is the key).
3. The 27 dacomp-*.sqlite databases sitting in database/
   (download from https://huggingface.co/datasets/DAComp/dacomp-da — see
   database/README.md).
4. The DB-GPT clone + the canonical session driver reachable on this host.
   By default the runner expects them under the repo:
       DBGPT_ROOT   : ./DB-GPT/                  (upstream DB-GPT clone)
       DBGPT_DRIVER : ./scripts/dbgpt_driver/    (dbgpt_session.py +
                                                  llm_instrumentation.py)
   Override with --dbgpt-root / --dbgpt-driver or the matching env vars.

Output layout
-------------
    transcripts/
      Hijack/
        T1.1/ T1.1__dacomp-001__tpl1.json ... (25 each, × 6 techniques)
        T1.2/ ...
        ...
      Mislead/
        T4.1/ T4.1__dacomp-072__tpl1.json ... (25 each, × 4 techniques)
        ...
      Drain/
        T6.1/ ... (25 each, × 4 techniques)
        ...
    scripts/run_logs/run_<TS>/summary.csv      one row per manifest

Usage
-----
    python scripts/run_dbgpt_attacks.py                          # all 350
    python scripts/run_dbgpt_attacks.py --group Mislead          # 100
    python scripts/run_dbgpt_attacks.py --technique T1.1         # one cell
    python scripts/run_dbgpt_attacks.py --test-id T1.1__dacomp-001__tpl1
    python scripts/run_dbgpt_attacks.py --smoke                  # 1 per group
    python scripts/run_dbgpt_attacks.py --dry-run                # no API calls
    python scripts/run_dbgpt_attacks.py --parallel 4 --timeout 1800
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("missing dependency: pip install pyyaml")


# ====================================================================
# Paths — everything relative to repo root (DataAgentSecurity_Test/)
# ====================================================================
THIS_FILE  = Path(__file__).resolve()
REPO_ROOT  = THIS_FILE.parent.parent                              # DataAgentSecurity_Test/
TESTCASE   = REPO_ROOT / "test_case"
DATABASES  = REPO_ROOT / "database"
ENV_DIR    = REPO_ROOT / "env"
KEY_FILE   = ENV_DIR / "YOUR_OPENROUTER_KEY.txt"
DOCKERFILE = ENV_DIR / "Dockerfile.dataagent"
TRANSCRIPTS_ROOT = REPO_ROOT / "transcripts"
RUN_LOGS_ROOT    = REPO_ROOT / "scripts" / "run_logs"

# DB-GPT clone + the canonical session driver. Defaults assume a
# self-contained layout inside this repo (see README). Overridable via env
# vars (DBGPT_ROOT, DBGPT_DRIVER) or CLI flags.
DBGPT_ROOT   = Path(os.environ.get(
    "DBGPT_ROOT",
    str(REPO_ROOT / "DB-GPT")))
DBGPT_DRIVER = Path(os.environ.get(
    "DBGPT_DRIVER",
    str(REPO_ROOT / "scripts" / "dbgpt_driver")))

# Sandbox image identifier — must match what env/Dockerfile.dataagent builds.
SANDBOX_IMAGE = os.environ.get("DBGPT_DOCKER_IMAGE", "dbgpt-sandbox:py311-data")

# Groups → technique listing (matches the manifest layout)
GROUPS = {
    "Hijack":  ["T1.1", "T1.2", "T2.1", "T2.2", "T3.1", "T3.2"],
    "Mislead": ["T4.1", "T4.2", "T5.1", "T5.2"],
    "Drain":   ["T6.1", "T6.2", "T7.1", "T7.2"],
}

_csv_lock = threading.Lock()


# ====================================================================
# Pre-flight checks
# ====================================================================

def read_openrouter_key(path: Path) -> str:
    if not path.exists():
        sys.exit(f"missing key file: {path}\n"
                 f"create it with your OpenRouter key (see env/README.md).")
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s == "sk-or-v1-REPLACE_ME_WITH_YOUR_KEY":
            sys.exit(f"{path} still holds the placeholder — paste your real key.")
        return s
    sys.exit(f"{path} contains no key (only blanks/comments).")


def verify_docker_and_image(image: str, allow_missing: bool = False) -> None:
    """Verify Docker daemon and sandbox image. If allow_missing, only warn."""
    try:
        subprocess.run(["docker", "info"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (FileNotFoundError, subprocess.CalledProcessError):
        sys.exit("Docker daemon not reachable.\n"
                 "  Start the daemon (`sudo systemctl start docker` / Docker Desktop).")
    r = subprocess.run(["docker", "image", "inspect", image],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r.returncode != 0:
        msg = (f"Docker image {image!r} not found.\n"
               f"Build it first:\n"
               f"  docker build -f {DOCKERFILE} -t {image} {ENV_DIR}")
        if allow_missing:
            print(f"[warn] {msg}", file=sys.stderr)
        else:
            sys.exit(msg)


def verify_database_dir(needed_dbs: set[str]) -> None:
    missing = [d for d in sorted(needed_dbs)
               if not (DATABASES / f"{d}.sqlite").exists()]
    if missing:
        sys.exit(f"missing {len(missing)} dacomp DB(s) in {DATABASES}:\n"
                 f"  {missing[:5]}{'...' if len(missing) > 5 else ''}\n"
                 f"see database/README.md for how to download dacomp-da.")


def add_upstream_to_path() -> None:
    """Make the DB-GPT driver + the DB-GPT packages importable."""
    for p in [
        str(DBGPT_DRIVER),
        str(DBGPT_ROOT / "packages" / "dbgpt-core" / "src"),
        str(DBGPT_ROOT / "packages" / "dbgpt-app" / "src"),
        str(DBGPT_ROOT / "packages" / "dbgpt-serve" / "src"),
    ]:
        if Path(p).exists() and p not in sys.path:
            sys.path.insert(0, p)
    for stem in ("dbgpt_session", "llm_instrumentation"):
        try:
            __import__(stem)
        except ImportError as e:
            sys.exit(f"cannot import {stem!r} from {DBGPT_DRIVER}: {e}")


# ====================================================================
# Manifest loading + filtering
# ====================================================================

def load_manifest(path: Path) -> dict:
    d = yaml.safe_load(path.read_text())
    d["_manifest_path"] = str(path)
    return d


def discover_manifests(groups: list[str]) -> list[dict]:
    out = []
    for g in groups:
        d = TESTCASE / g / "manifests"
        if not d.exists():
            print(f"[warn] no manifests dir at {d}", file=sys.stderr)
            continue
        for f in sorted(d.glob("*.yaml")):
            m = load_manifest(f)
            m["_group"] = g
            out.append(m)
    return out


def filter_manifests(manifests: list[dict], args: argparse.Namespace) -> list[dict]:
    out = list(manifests)
    if args.group:
        out = [m for m in out if m["_group"] in set(args.group)]
    if args.technique:
        out = [m for m in out if m["technique"] in set(args.technique)]
    if args.test_id:
        out = [m for m in out if m["test_id"] in set(args.test_id)]
    if args.db:
        out = [m for m in out if m["db"] in set(args.db)]
    if args.limit:
        out = out[: args.limit]
    if args.smoke:
        # One per group present (smaller manifests preferred for fast smoke)
        chosen: dict[str, dict] = {}
        # Prefer single_turn for fast smoke; fall back to anything.
        for m in out:
            g = m["_group"]
            if g in chosen: continue
            if m.get("interaction_mode") == "single_turn":
                chosen[g] = m
        for m in out:
            chosen.setdefault(m["_group"], m)
        out = list(chosen.values())
        out.sort(key=lambda m: (m["_group"], m["test_id"]))
    return out


# ====================================================================
# Per-manifest workspace
# ====================================================================

def prepare_workspace(workspace: Path, manifest: dict, group: str) -> tuple[Path, list[str]]:
    """Set up the workspace for one manifest.

    Returns (db_relpath, aux_file_paths). The agent sees the DB at
    `./<db>.sqlite` and aux files at `./<name>` (one level under workspace).
    """
    workspace.mkdir(parents=True, exist_ok=True)

    # 1. Copy the DB from database/ into the workspace
    src_db = DATABASES / f"{manifest['db']}.sqlite"
    if not src_db.exists():
        raise FileNotFoundError(f"DB not found: {src_db}")
    target_db = workspace / src_db.name
    shutil.copy2(src_db, target_db)
    os.chmod(target_db, 0o644)

    # 2. If mutate_db, apply injection_sql
    if manifest.get("mutate_db") and manifest.get("injection_sql"):
        conn = sqlite3.connect(str(target_db))
        try:
            conn.executescript(manifest["injection_sql"])
            conn.commit()
        finally:
            conn.close()
    else:
        # Read-only when no mutation is expected (mirrors hijack_workspace.py)
        os.chmod(target_db, 0o444)

    # 3. Copy aux files (Mislead T4.2 / T5.1 mostly)
    aux_paths: list[str] = []
    for item in manifest.get("aux_files") or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        src = item.get("src")
        if not name:
            continue
        src_path = None
        if src:
            p = Path(src)
            src_path = p if p.is_absolute() else (REPO_ROOT / p)
        # Fall back to test_case/<Group>/aux_files/<test_id>/<name>
        if not src_path or not src_path.exists():
            src_path = TESTCASE / group / "aux_files" / manifest["test_id"] / name
        if not src_path.exists():
            raise FileNotFoundError(f"aux file not found for {manifest['test_id']}: {name}")
        dst_path = workspace / name
        shutil.copy2(src_path, dst_path)
        os.chmod(dst_path, 0o444)
        aux_paths.append(str(dst_path))

    db_relpath = f"./{target_db.name}"
    return target_db, aux_paths


def cleanup_workspace(workspace: Path) -> None:
    if workspace.exists():
        shutil.rmtree(workspace, ignore_errors=True)


# ====================================================================
# Turn building (single-turn or multi-turn)
# ====================================================================

def build_turns(manifest: dict, db_relpath: str) -> list[str]:
    prompt = manifest.get("prompt", "")
    canonical = f"./{manifest['db']}.sqlite"
    prompt = prompt.replace(canonical, db_relpath)
    if manifest.get("interaction_mode") == "multi_turn" and manifest.get("turns"):
        turns = [t.replace(canonical, db_relpath) for t in manifest["turns"]]
        return turns
    return [prompt]


# ====================================================================
# Driving DB-GPT for one manifest
# ====================================================================

def run_one(manifest: dict, args: argparse.Namespace, run_dir: Path,
            llm_cfg: dict) -> dict:
    """Run one manifest end-to-end. Returns a summary dict (1 CSV row)."""
    group = manifest["_group"]
    tech = manifest["technique"]
    test_id = manifest["test_id"]
    workspace = run_dir / "workspaces" / test_id
    cleanup_workspace(workspace)
    out_dir = TRANSCRIPTS_ROOT / group / tech
    out_dir.mkdir(parents=True, exist_ok=True)
    transcript_path = out_dir / f"{test_id}.json"

    try:
        target_db, aux_paths = prepare_workspace(workspace, manifest, group)
        db_relpath = f"./{target_db.name}"
        turns = build_turns(manifest, db_relpath)
    except Exception as e:
        traceback.print_exc()
        return {"test_id": test_id, "group": group, "technique": tech,
                "status": "WORKSPACE_ERROR", "error": str(e),
                "elapsed_s": 0, "transcript": ""}

    if args.dry_run:
        # No API call — write a stub transcript proving wiring works.
        stub = {**{k: manifest.get(k) for k in
                   ("test_id", "technique", "template_id", "template_mechanism",
                    "db", "host_table", "host_column", "interaction_mode",
                    "mutate_db", "expected_violation_clauses", "asr_signal",
                    "asr_real_values", "clean_baseline_value",
                    "poisoned_target_value", "expected_bias_direction",
                    "prompt", "injection_sql", "aux_files")},
                "manifest_path": manifest.get("_manifest_path"),
                "workspace": str(workspace),
                "db_file": str(target_db),
                "turns_sent": turns,
                "aux_file_paths": aux_paths,
                "responses": [], "code_cells": [], "code_outputs": [],
                "full_output": "", "messages": [],
                "elapsed_s": 0.0, "token_usage": None,
                "error": "DRY_RUN — no API call made"}
        transcript_path.write_text(json.dumps(stub, indent=2, ensure_ascii=False,
                                                default=str))
        print(f"  [dry-run] {test_id} → {transcript_path.name}")
        return {"test_id": test_id, "group": group, "technique": tech,
                "status": "DRY_RUN", "error": "",
                "elapsed_s": 0, "transcript": str(transcript_path)}

    # Real run — call the canonical session driver.
    from dbgpt_session import run_dbgpt_session  # type: ignore

    t_start = time.time()
    try:
        result = run_dbgpt_session(
            turns=turns,
            data_files=aux_paths,            # aux files (Mislead T4.2/T5.1)
            timeout=args.timeout,
            workspace_dir=workspace,
            llm_cfg=llm_cfg,
            preserve_workspace=True,         # we already placed the DB
        )
    except Exception as e:
        traceback.print_exc()
        cleanup_workspace(workspace)
        return {"test_id": test_id, "group": group, "technique": tech,
                "status": "SESSION_EXCEPTION", "error": f"{type(e).__name__}: {e}",
                "elapsed_s": time.time() - t_start, "transcript": ""}

    transcript = {**{k: manifest.get(k) for k in
                     ("test_id", "technique", "template_id", "template_mechanism",
                      "db", "host_table", "host_column", "interaction_mode",
                      "mutate_db", "expected_violation_clauses", "asr_signal",
                      "asr_real_values", "clean_baseline_value",
                      "poisoned_target_value", "expected_bias_direction",
                      "prompt", "injection_sql", "aux_files")},
                  "manifest_path": manifest.get("_manifest_path"),
                  "workspace": str(workspace),
                  "db_file": str(target_db),
                  "turns_sent": turns,
                  "aux_file_paths": aux_paths,
                  "elapsed_s": round(result.get("elapsed", 0.0), 2),
                  "token_usage": result.get("token_usage"),
                  "error": result.get("error"),
                  "responses": result.get("responses", []),
                  "code_cells": result.get("code_cells", []),
                  "code_outputs": result.get("code_outputs", []),
                  "messages": result.get("messages", []),
                  "full_output": result.get("full_output", "")}
    transcript_path.write_text(json.dumps(transcript, indent=2, ensure_ascii=False,
                                            default=str))

    if not args.keep_workspaces:
        cleanup_workspace(workspace)

    return {"test_id": test_id, "group": group, "technique": tech,
            "status": "OK" if not result.get("error") else "RUN_ERROR",
            "error": result.get("error") or "",
            "elapsed_s": round(result.get("elapsed", 0.0), 2),
            "transcript": str(transcript_path)}


# ====================================================================
# Main
# ====================================================================

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--group", action="append",
                   choices=list(GROUPS.keys()),
                   help="restrict to a group (repeatable). default: all")
    p.add_argument("--technique", action="append",
                   help="restrict to a technique (repeatable). default: all")
    p.add_argument("--test-id", action="append", dest="test_id",
                   help="run only these specific test_ids (repeatable)")
    p.add_argument("--db", action="append",
                   help="restrict to specific dacomp DBs (repeatable)")
    p.add_argument("--limit", type=int, default=None,
                   help="cap the total number of manifests after filtering")
    p.add_argument("--smoke", action="store_true",
                   help="run one manifest per group to verify wiring")
    p.add_argument("--dry-run", action="store_true",
                   help="prepare workspace + write a stub transcript; do NOT call DB-GPT")
    p.add_argument("--parallel", type=int, default=3,
                   help="thread-pool size for concurrent runs (default: 3)")
    p.add_argument("--timeout", type=int, default=1200,
                   help="per-manifest timeout in seconds (default: 1200)")
    p.add_argument("--model", default=os.environ.get(
                       "OPENROUTER_MODEL", "deepseek/deepseek-v3.2"),
                   help="OpenRouter model id (default: deepseek/deepseek-v3.2)")
    p.add_argument("--api-base", default="https://openrouter.ai/api/v1")
    p.add_argument("--openrouter-provider", default="AtlasCloud",
                   help="OpenRouter provider pin (passed to llm_instrumentation)")
    p.add_argument("--openrouter-allow-fallbacks", action="store_true")
    p.add_argument("--keep-workspaces", action="store_true",
                   help="don't delete per-manifest workspaces after the run")
    p.add_argument("--allow-missing-image", action="store_true",
                   help="warn instead of erroring when the docker image isn't built "
                        "(useful with --dry-run)")
    p.add_argument("--dbgpt-root", default=str(DBGPT_ROOT),
                   help=f"path to upstream DB-GPT repo (default: {DBGPT_ROOT})")
    p.add_argument("--dbgpt-driver", default=str(DBGPT_DRIVER),
                   help=f"path to the DB-GPT session driver "
                        f"(default: {DBGPT_DRIVER})")
    return p


def main() -> int:
    args = build_argparser().parse_args()

    # Resolve upstream overrides
    global DBGPT_ROOT, DBGPT_DRIVER
    DBGPT_ROOT   = Path(args.dbgpt_root)
    DBGPT_DRIVER = Path(args.dbgpt_driver)

    # ── 0. Read key & set env
    key = read_openrouter_key(KEY_FILE) if not args.dry_run else "DRY_RUN_KEY"
    os.environ["OPENROUTER_API_KEY"] = key
    os.environ["DBGPT_USE_DOCKER"] = "1" if not args.dry_run else "0"
    os.environ["DBGPT_DOCKER_IMAGE"] = SANDBOX_IMAGE

    # ── 1. Pre-flight: docker, manifests, DBs
    if not args.dry_run:
        verify_docker_and_image(SANDBOX_IMAGE,
                                allow_missing=args.allow_missing_image)
    print(f"[setup] DBGPT_USE_DOCKER={os.environ['DBGPT_USE_DOCKER']}, "
          f"image={SANDBOX_IMAGE}")
    print(f"[setup] OpenRouter key loaded ({len(key)} chars), "
          f"model={args.model}, provider={args.openrouter_provider}")

    # ── 2. Load + filter manifests
    groups_to_load = args.group or list(GROUPS.keys())
    all_manifests = discover_manifests(groups_to_load)
    selected = filter_manifests(all_manifests, args)
    print(f"[setup] discovered {len(all_manifests)} manifest(s), "
          f"running {len(selected)}")
    if not selected:
        print("nothing to run."); return 1

    # ── 3. Verify needed DBs
    needed_dbs = {m["db"] for m in selected}
    if not args.dry_run:
        verify_database_dir(needed_dbs)

    # ── 4. Import dbgpt_session (and install OpenRouter provider pin)
    if not args.dry_run:
        add_upstream_to_path()
        try:
            import llm_instrumentation     # noqa: F401
            llm_instrumentation.install(
                provider_name=args.openrouter_provider,
                allow_fallbacks=bool(args.openrouter_allow_fallbacks))
            print(f"[setup] OpenRouter provider pin installed: "
                  f"{args.openrouter_provider}")
        except Exception as e:
            print(f"[warn] provider pin not installed: {e}", file=sys.stderr)

    # ── 5. Per-run state
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUN_LOGS_ROOT / f"run_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "summary.csv"
    with summary_path.open("w", newline="") as f:
        csv.writer(f).writerow(
            ["test_id", "group", "technique", "status", "elapsed_s",
             "error", "transcript"])

    llm_cfg = {"api_base": args.api_base, "api_key": key,
                "model": args.model, "timeout": args.timeout}

    # ── 6. Run (parallel)
    print(f"[run] {len(selected)} manifests across {args.parallel} workers"
          f" → {TRANSCRIPTS_ROOT}\n")
    ok = err = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=max(1, args.parallel)) as pool:
        futs = {pool.submit(run_one, m, args, run_dir, llm_cfg): m for m in selected}
        for i, fut in enumerate(as_completed(futs), 1):
            row = fut.result()
            with _csv_lock, summary_path.open("a", newline="") as f:
                csv.writer(f).writerow(
                    [row["test_id"], row["group"], row["technique"],
                     row["status"], row["elapsed_s"], row["error"],
                     row["transcript"]])
            tag = "✓" if row["status"] in ("OK", "DRY_RUN") else "✗"
            if row["status"] in ("OK", "DRY_RUN"): ok += 1
            else: err += 1
            print(f"[{i}/{len(selected)}] {tag} {row['test_id']:<48} "
                  f"{row['status']:<18} {row['elapsed_s']:>6.1f}s "
                  f"{row['error'][:60]}")

    dt = time.time() - t0
    print(f"\n[done] {ok} ok, {err} failed; {dt:.1f}s wall; "
          f"summary={summary_path}")
    return 0 if err == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())

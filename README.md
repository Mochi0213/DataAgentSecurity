# DataAgentSecurity

Reproducibility package for the data agent security evaluation in our paper
*"Data Agents Under Attack: Vulnerabilities in LLM-Driven Analytical Systems"*.
This repo bundles all 350 attack payloads (as YAML manifests), the three ASR
judges, the DB-GPT runner, the sandbox Docker definition, and the DAComp-DA
database download instructions. Our technical report is in
[`technical_report.pdf`](technical_report.pdf).

The benchmark covers three adversary goals and 14 attack techniques. Each
technique has 25 payloads (5 templates × 5 databases), for 350 payloads in
total:

| Goal    | Techniques                                | # payloads |
|:--------|:------------------------------------------|--------:|
| Hijack  | T1.1, T1.2, T2.1, T2.2, T3.1, T3.2        |        150 |
| Mislead | T4.1, T4.2, T5.1, T5.2                    |        100 |
| Drain   | T6.1, T6.2, T7.1, T7.2                    |        100 |

---

## 1 · Repository layout

```
DataAgentSecurity/
├── README.md                      
│
├── database/                      ← dacomp-*.sqlite databases
│   ├── README.md                  
│   └── DOWNLOAD_LINK.txt         
│
├── env/                           
│   ├── README.md
│   ├── Dockerfile.dataagent       
│   └── YOUR_OPENROUTER_KEY.txt    ← paste your OpenRouter key here
│
├── test_case/                     ← all 350 attack manifests
│   ├── Hijack/
│   │   ├── manifests/             ← 150 Hijack YAMLs
│   │   └── templates/             ← Hijack templates
│   │
│   ├── Mislead/
│   │   ├── manifests/             ← 100 Mislead YAMLs
│   │   ├── templates/             
│   │   └── aux_files/                                      
│   │
│   └── Drain/
│       ├── manifests/             ← 100 Drain YAMLs
│       ├── templates/             
│       └── benign_baselines/      ← 14 benign-workload YAMLs
│                                     
│                                     
│
├── scripts/
│   ├── run_dbgpt_attacks.py       ← Drives 350 Hijack + Mislead + Drain manifests through DB-GPT
│   │
│   ├── judge_rules/               ← ASR judges used to score saved transcripts
│   │   ├── hijack_judge.py        ← Hijack ASR judge
│   │   ├── mislead_judge.py       ← Mislead ASR judge
│   │   └── drain_judge.py         ← Drain ASR judge
│   │
│   ├── plotting/                  ← scripts for regenerating paper figures
│   │   ├── fig2(b).py
│   │   ├── fig3.py
│   │   ├── fig4.py
│   │   └── fig5.py
│   │
│   └── run_logs/                  ← per-run CSV summary, created by the runner
│
├── DB-GPT/                        ← upstream DB-GPT, cloned in Step 1
│
└── transcripts/                   ← Checked-in transcripts for reproducing ASR
    ├── Hijack/
    │   ├── T1.1/*.json
    │   ├── T1.2/*.json
    │   ├── T2.1/*.json
    │   ├── T2.2/*.json
    │   ├── T3.1/*.json
    │   └── T3.2/*.json
    │
    ├── Mislead/
    │   ├── T4.1/*.json
    │   ├── T4.2/*.json
    │   ├── T5.1/*.json
    │   └── T5.2/*.json
    │
    └── Drain/
        ├── T6.1/*.json
        ├── T6.2/*.json
        ├── T7.1/*.json
        ├── T7.2/*.json
        └── _baselines/            ← token/time baselines for Drain
```

Each technique has **25 transcript JSONs** (one per payload) under
`transcripts/<Group>/<Technique>/`. The judges turn them into the
per-technique ASR reported in the paper. Because the transcript JSONs are included in this repository,
the reported ASR results can be reproduced directly from `transcripts/` and
`scripts/judge_rules/` without rerunning any data-agent system.

---

## 2 · Reproducing the DB-GPT experiment

### Step 1 · Clone DB-GPT

```bash
cd DataAgentSecurity
git clone https://github.com/eosphoros-ai/DB-GPT.git
```

The runner discovers DB-GPT via `--dbgpt-root` (default: `./DB-GPT`).

### Step 2 · Drop in the session driver

The runner uses the OpenRouter-pinned session driver
(`dbgpt_session.py` + `llm_instrumentation.py`) we used in the paper.
Place them under `scripts/dbgpt_driver/`:

```bash
mkdir -p scripts/dbgpt_driver
cp <somewhere>/dbgpt_session.py        scripts/dbgpt_driver/
cp <somewhere>/llm_instrumentation.py  scripts/dbgpt_driver/
```

(Override with `--dbgpt-driver <path>` or env `DBGPT_DRIVER=…` if you
keep the driver elsewhere.)

### Step 3 · Build the Docker sandbox

DB-GPT executes generated code inside a container. Without this step, the
T1.2 (Code Injection) ASR is inflated because code runs on the host.

```bash
docker build -f env/Dockerfile.dataagent -t dbgpt-sandbox:py311-data env/
docker image inspect dbgpt-sandbox:py311-data >/dev/null && echo OK
```

### Step 4 · Add your OpenRouter API key

```bash
# Edit env/YOUR_OPENROUTER_KEY.txt — paste the key on the first
# non-comment line (replaces the placeholder).
nano env/YOUR_OPENROUTER_KEY.txt
```

The runner reads the first non-`#`, non-blank line.

### Step 5 · Download DAComp-DA databases

The benchmark uses 27 DAComp-DA databases. The `.sqlite` files live on
Hugging Face:

```bash
huggingface-cli download DAComp/dacomp-da \
    --repo-type dataset --local-dir ./database
ls database/dacomp-*.sqlite | wc -l
```

(See `database/README.md` for `git lfs` / manual-download alternatives.)

### Step 6 · Smoke-test the wiring

Without consuming OpenRouter credits, exercise everything except the API:

```bash
python scripts/run_dbgpt_attacks.py --smoke --dry-run
```

You should see 3 ✓ rows (one per group), and three stub transcripts
appear under `transcripts/{Hijack,Mislead,Drain}/<tech>/`. Delete them
before the real run:

```bash
rm -rf transcripts scripts/run_logs
```

### Step 7 · Run the full benchmark

```bash
# all 350 payloads, 4 workers, 1,800 s cap per test (as in the paper)
python scripts/run_dbgpt_attacks.py --parallel 4 --timeout 1800
```

Subset filters (each repeatable):

```bash
python scripts/run_dbgpt_attacks.py --group Hijack
python scripts/run_dbgpt_attacks.py --technique T1.2 --technique T5.2
python scripts/run_dbgpt_attacks.py --test-id T4.1__dacomp-072__tpl1
python scripts/run_dbgpt_attacks.py --db dacomp-001 --db dacomp-019
python scripts/run_dbgpt_attacks.py --limit 10
```

Outputs:

```
transcripts/<Group>/<Technique>/<test_id>.json    – 350 JSON transcripts
scripts/run_logs/run_<TIMESTAMP>/summary.csv      – one row per manifest
```

If you only want to reproduce the paper ASR numbers, you can skip the full
DB-GPT run and use the checked-in transcripts directly with the judges in
Section 3.

---

## 3 · Running the ASR judges

The checked-in `transcripts/` directory is sufficient to reproduce the ASR
results. The three judges are zero-configuration for Hijack and Mislead: each
defaults to its own `transcripts/<Group>/` sub-tree, walks every JSON
underneath, and writes `<Group>/_judge/{review.csv, summary.csv}` next to the
transcripts. Drain additionally uses the baseline CSVs under
`transcripts/Drain/_baselines/`.

```bash
# Hijack (T1.1, T1.2, T2.1, T2.2, T3.1, T3.2)
python scripts/judge_rules/hijack_judge.py

# Mislead (T4.1, T4.2, T5.1, T5.2)
python scripts/judge_rules/mislead_judge.py

# Drain (T6.1, T6.2, T7.1, T7.2)
python scripts/judge_rules/drain_judge.py \
    --baselines transcripts/Drain/_baselines/DB-GPT__calibrated_baselines.csv
```

`review.csv` gives the verdict and evidence for each test; `summary.csv` gives
the per-technique totals (total / errors / successes / ASR%). The three
`summary.csv` files (Hijack, Mislead, Drain) give the per-technique ASR shown
in the paper's ASR heatmap.

To judge transcripts from another system, pass its directory as the first
argument, e.g. `python scripts/judge_rules/hijack_judge.py transcripts/BigQuery/Hijack`.

---

## 4 · Other open-source systems (LAMBDA, DeepAnalyze, DataInterpreter)

LAMBDA, DeepAnalyze (DA), and DataInterpreter (the analyst role inside
MetaGPT) follow **the exact same flow** as DB-GPT — only the runner
differs. For each:

1. Clone the system under `DataAgentSecurity/<SYSTEM>/` (or set up
   its API server / vLLM endpoint per its own README).
2. Write or adapt a runner mirroring `scripts/run_dbgpt_attacks.py` —
   replace the `run_dbgpt_session` call site with the system's session
   driver (e.g. LAMBDA's notebook-kernel client, DA's `/api/chat`,
   MetaGPT's `DataInterpreter.run()`).
3. Workspace prep (`prepare_workspace`), aux-file copying, manifest
   filtering, and transcript schema (`responses` / `code_cells` /
   `code_outputs` / `full_output` / `token_usage`) stay identical, so
   the three judges work without modification.
4. Save the resulting transcripts under
   `transcripts/<SYSTEM>/<Group>/<Technique>/` and run the judges on that
   directory as in §3.

Reproducing the paper's ASR requires every system to write the same
transcript schema.

---

## 5 · Other closed-source systems (Databricks Genie, BigQuery Conversational Agent)

These two ship as cloud-only products; their experiment flows differ.

### Databricks Genie Code — web-driven

Genie Code has no public scripting API for the attack surface we test, so the
canonical procedure is **manual webpage interaction**:

1. Sign in to your Databricks workspace.
2. For each manifest:
   - Upload the prepared DB (`database/<db>.sqlite` with `injection_sql`
     applied if `mutate_db: true`) and any aux files
     (`test_case/Mislead/aux_files/<test_id>/*`) into the Genie data
     room.
   - Paste the manifest's `prompt` field into the Genie chat.
   - Save Genie's full reply transcript + final answer.
3. Convert the saved reply into the standard transcript JSON schema and
   save it at `transcripts/Databricks/<Group>/<Technique>/<test_id>.json`,
   then run the judges on that directory (§3).

A single human round-trip per cell is enough; we did not parallelise
this in the paper.

### BigQuery Conversational Agent — CLI-driven

Like Databricks Genie, BigQuery's Conversational Agent (the chat
front-end backed by Gemini-in-BigQuery) has no public attack-surface
SDK. Instead, you script the round-trip locally by (a) authenticating
to a BigQuery project, (b) uploading each manifest's DB as a BigQuery
dataset, and (c) posting the manifest's `prompt` to the agent's
conversational endpoint with the dataset attached. The flow is the
exact CLI analogue of the Databricks Genie procedure above:

**One-time setup**

1. Authenticate locally:
   ```bash
   gcloud auth application-default login
   gcloud config set project <YOUR_BIGQUERY_PROJECT>
   ```
2. Enable the BigQuery API + Conversational Agent (Gemini in BigQuery)
   in the Google Cloud console for that project.
3. Install client libs:
   ```bash
   pip install google-cloud-bigquery google-cloud-aiplatform
   ```

**Per manifest** (write a small wrapper script — analogous to
`scripts/run_dbgpt_attacks.py` but for BigQuery):

1. Read the manifest YAML from
   `test_case/<Group>/manifests/<test_id>.yaml`.
2. **Build the BigQuery dataset** for the manifest:
   - Create a fresh dataset named after `manifest['db']`
     (e.g. `dacomp_001`).
   - Load every table from the corresponding SQLite file
     `database/<db>.sqlite` into the dataset
     (e.g. via `pandas.read_sql` → `bigquery.Client.load_table_from_dataframe`).
   - If `mutate_db: true`, translate `injection_sql` (SQLite dialect) to
     BigQuery SQL and run it via `bq query --use_legacy_sql=false` or
     `bigquery.Client.query()`. Most of our manifests use plain
     `INSERT INTO …` which is portable as-is.
   - For Mislead T4.2 / T5.1, also upload each entry in
     `test_case/Mislead/aux_files/<test_id>/` into a sibling staging
     dataset or as a Cloud Storage object the agent can read.
3. **Submit the prompt** to the Conversational Agent — wrapping the
   manifest's `prompt` field verbatim, with the new dataset declared as
   the active context. Capture the agent's complete reply, including any
   intermediate SQL it ran and the final answer it printed.
4. **Save as a standard transcript**: serialise the reply into the same
   JSON schema the DB-GPT runner produces (`test_id`, `technique`, `db`,
   `prompt`, `responses`, `code_cells`, `code_outputs`, `full_output`,
   `token_usage`, `elapsed_s`, `error`) and write it to
   `transcripts/BigQuery/<Group>/<Technique>/<test_id>.json`.
5. Delete the dataset, or keep it for auditing.

Then run the three judges from §3 on `transcripts/BigQuery/<Group>/`. No
judge changes are needed.

**Architectural N/A cells.** BigQuery cannot evaluate arbitrary
Python or shell, and is single-engine SQL. The cells the BigQuery
agent cannot legitimately attempt are:

- T1.2, T4.2 & T6.2

Report these as N/A, as in the paper.

---

## 6 · Acknowledgements & licence

- The 27 DAComp-DA databases are released by the DAComp team under their
  Hugging Face dataset card; cite the dataset there.
- DB-GPT, MetaGPT, DeepAnalyze, LAMBDA are released under their own
  upstream licences — see each project's repository for terms.
- This benchmark repo is intended for academic reproducibility. Do not
  point the runner at any DB / data-room that contains real PII.

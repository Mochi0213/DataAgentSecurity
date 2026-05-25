# Database — DAComp-DA SQLite Files

This directory holds the 27 SQLite databases that all manifests in
`test_case/{Hijack,Mislead,Drain}/manifests/` reference via their `db` /
`db_file` fields. **The actual `.sqlite` files are not bundled with this
repo — you must download them from the public DAComp-DA dataset before
running any test.**

## Download

The 27 SQLite databases live on Hugging Face Datasets:

**<https://huggingface.co/datasets/DAComp/dacomp-da>**

After downloading, place the files directly under this directory:

```
./database/                        (this dir, relative to repo root)
├── dacomp-001.sqlite
├── dacomp-007.sqlite
├── dacomp-017.sqlite
├── ... (27 files total)
└── dacomp-092.sqlite
```

### Option A — `huggingface-cli` (recommended)

All commands below assume your shell is in the **repository root**
(`DataAgentSecurity_Test/`); paths are relative.

```bash
# install once: pip install -U "huggingface_hub[cli]"
huggingface-cli download DAComp/dacomp-da \
    --repo-type dataset \
    --local-dir ./database
```

### Option B — `git lfs`

```bash
git lfs install
git clone https://huggingface.co/datasets/DAComp/dacomp-da database
```

### Option C — manual

Visit the dataset page in a browser and download each `.sqlite` file
listed in the manifest below; drop them into this directory.

## DBs referenced by the test manifests (27 total)

```
dacomp-001  dacomp-007  dacomp-017  dacomp-019  dacomp-021
dacomp-025  dacomp-034  dacomp-043  dacomp-044  dacomp-048
dacomp-054  dacomp-055  dacomp-061  dacomp-063  dacomp-067
dacomp-072  dacomp-073  dacomp-080  dacomp-081  dacomp-083
dacomp-084  dacomp-085  dacomp-086  dacomp-089  dacomp-090
dacomp-091  dacomp-092
```

## Verifying the download

After download, this command should print `27`:

```bash
ls ./database/dacomp-*.sqlite | wc -l
```

If you get fewer, double-check the dataset card on Hugging Face — the
repo occasionally adds new DBs that are not yet wired into our manifests
(extras are harmless; missing DBs will cause runner errors at start-up).

## How the runners resolve DB paths

Each manifest carries two fields:

```yaml
db:      dacomp-019                              # logical id
db_file: databases/dacomp-019.sqlite             # historical relative path
```

The runners look for the file using one of:

- `<workspace>/databases/<db>.sqlite` (legacy layout)
- `./database/<db>.sqlite` (new layout — this dir, relative to repo root)

If your runner uses the legacy `databases/` (plural) path, either rename
this directory to `databases` or create a symlink:

```bash
ln -s database databases   # run from the repo root
```

## License / Source

The DAComp-DA dataset is released by the DAComp team under the licence
stated on its Hugging Face page. See
<https://huggingface.co/datasets/DAComp/dacomp-da> for citation, terms
of use, and origin of each constituent database.

from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt

OUT_DIR = Path(__file__).resolve().parent

AXES = [
    "V1\nTrust Bias",
    "V2\nSource Verification",
    "V3\nQuery Cost",
    "V4\nEngine Divergence",
    "V5\nUnbounded Chains",
    "V6\nPolicy Forgetting",
    "V7\nOver-Privilege",
    "V8\nComposition Leak",
]
VULN_IDS = ["V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8"]

COLORS = {
    "DataInterpreter": "#B9857A",
    "DeepAnalyze":     "#D1B07A",
    "DB-GPT":          "#8EAA8B",
    "LAMBDA":          "#6F95B2",
    "Databricks":      "#7B6B9F",   # purple
    "BigQuery":        "#3D8B9E",   # teal / cyan
}
MARKERS = {
    "DataInterpreter": "o", "DeepAnalyze": "s", "DB-GPT": "^", "LAMBDA": "D",
    "Databricks": "v", "BigQuery": "*",
}
# safe filename per system
FNAME = {
    "DataInterpreter": "DataInterpreter",
    "DeepAnalyze":     "DeepAnalyze",
    "DB-GPT":          "DB-GPT",
    "LAMBDA":          "LAMBDA",
    "Databricks":      "Databricks",
    "BigQuery":        "BigQuery",
}

# Per-(system, technique) ASR (%). None == N/A → 0 on that axis.
ASR = {
    "T1.1": {"DataInterpreter": 20, "DB-GPT": 24, "DeepAnalyze":   0, "LAMBDA": 48,
              "Databricks":  0, "BigQuery":   24},
    "T1.2": {"DataInterpreter": 56, "DB-GPT": 68, "DeepAnalyze":  16, "LAMBDA": 28,
              "Databricks":  0, "BigQuery": None},
    "T2.1": {"DataInterpreter":  0, "DB-GPT": 44, "DeepAnalyze":  16, "LAMBDA": 64,
              "Databricks":  0, "BigQuery":   24},
    "T2.2": {"DataInterpreter": 40, "DB-GPT": 24, "DeepAnalyze":  56, "LAMBDA": 28,
              "Databricks":  0, "BigQuery":    0},
    "T3.1": {"DataInterpreter":  8, "DB-GPT": 44, "DeepAnalyze":  32, "LAMBDA": 24,
              "Databricks":  0, "BigQuery":   12},
    "T3.2": {"DataInterpreter": 20, "DB-GPT": 40, "DeepAnalyze":  20, "LAMBDA": 28,
              "Databricks":  4, "BigQuery":   12},
    "T4.1": {"DataInterpreter":  0, "DB-GPT": 16, "DeepAnalyze":  40, "LAMBDA":  8,
              "Databricks": 24, "BigQuery":    8},
    "T4.2": {"DataInterpreter":  8, "DB-GPT": 20, "DeepAnalyze":  76, "LAMBDA": 24,
              "Databricks": 44, "BigQuery": None},
    "T5.1": {"DataInterpreter":  0, "DB-GPT": 52, "DeepAnalyze": 100, "LAMBDA": 16,
              "Databricks": 80, "BigQuery":   84},
    "T5.2": {"DataInterpreter":  8, "DB-GPT": 36, "DeepAnalyze":  68, "LAMBDA": 44,
              "Databricks": 80, "BigQuery":   88},
    "T6.1": {"DataInterpreter":  4, "DB-GPT": 32, "DeepAnalyze":  60, "LAMBDA": 36,
              "Databricks": 24, "BigQuery":   12},
    "T6.2": {"DataInterpreter": 12, "DB-GPT": 20, "DeepAnalyze":  12, "LAMBDA": 16,
              "Databricks": 40, "BigQuery": None},
    "T7.1": {"DataInterpreter":  4, "DB-GPT": 28, "DeepAnalyze":  68, "LAMBDA": 48,
              "Databricks": 76, "BigQuery":   16},
    "T7.2": {"DataInterpreter":  0, "DB-GPT": 56, "DeepAnalyze":  24, "LAMBDA": 52,
              "Databricks": 80, "BigQuery":    0},
}

TECH_VULNS = {
    "T1.1": ["V2"], "T1.2": ["V2"],
    "T2.1": ["V6"], "T2.2": ["V2", "V7"],
    "T3.1": ["V7", "V8"], "T3.2": ["V7", "V8"],
    "T4.1": ["V2"], "T4.2": ["V2"],
    "T5.1": ["V1"], "T5.2": ["V1"],
    "T6.1": ["V3"], "T6.2": ["V4"],
    "T7.1": ["V5"], "T7.2": ["V5"],
}


def compute_per_vuln(asr, tech_vulns, systems):
    vuln_techs = {v: [] for v in VULN_IDS}
    for tech, vs in tech_vulns.items():
        for v in vs:
            vuln_techs[v].append(tech)
    out = {s: [] for s in systems}
    for v in VULN_IDS:
        techs = vuln_techs[v]
        for s in systems:
            vals = [0.0 if asr[t][s] is None else float(asr[t][s]) for t in techs]
            out[s].append(round(sum(vals) / len(vals), 2) if vals else 0.0)
    return out


SYSTEMS = ["DataInterpreter", "DeepAnalyze", "DB-GPT", "LAMBDA",
            "Databricks", "BigQuery"]
DATA = compute_per_vuln(ASR, TECH_VULNS, SYSTEMS)

plt.rcParams.update({"font.family": "serif", "font.size": 13})


def draw_one(name: str, show_ytick_labels: bool = True) -> None:
    n = len(AXES)
    angles = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()
    angles += angles[:1]
    vals = DATA[name] + DATA[name][:1]

    fig, ax = plt.subplots(figsize=(4.4, 4.4), subplot_kw=dict(polar=True))
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)

    ax.plot(angles, vals, color=COLORS[name], linewidth=1.8,
            marker=MARKERS[name], markersize=4.5)
    ax.fill(angles, vals, color=COLORS[name], alpha=0.18)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(AXES, fontsize=12)
    ax.set_ylim(0, 100)
    ax.set_yticks([20, 40, 60, 80, 100])
    if show_ytick_labels:
        ax.set_yticklabels(["20", "40", "60", "80", "100"],
                            fontsize=11, color="#555555")
    else:
        ax.set_yticklabels([])      # keep grid circles, drop numeric labels
    ax.set_rlabel_position(112.5)
    ax.tick_params(axis="x", pad=10)
    ax.grid(color="#cccccc", linewidth=0.6)
    ax.spines["polar"].set_color("#999999")

    fig.tight_layout(pad=0.4)
    # No system name baked in -- the name is rendered in LaTeX (the {\scriptsize}
    # row under each radar in sections/4_vulnerabilities.tex).
    out = OUT_DIR / f"vuln_radar_{FNAME[name]}.pdf"
    fig.savefig(out, bbox_inches="tight")
    fig.savefig(str(out).replace(".pdf", ".png"), bbox_inches="tight", dpi=200)
    print(f"wrote {out}")
    plt.close(fig)


def main():
    print(f"{'':<16} " + "  ".join(f"{v:>6}" for v in VULN_IDS))
    for s in SYSTEMS:
        print(f"{s:<16} " + "  ".join(f"{v:>6.1f}" for v in DATA[s]))
    print()
    # Only the first figure (DataInterpreter, top-left of the 3x2 grid in §4)
    # carries the radial scale labels; the other five reuse it.
    for i, s in enumerate(SYSTEMS):
        draw_one(s, show_ytick_labels=(i == 0))


if __name__ == "__main__":
    main()

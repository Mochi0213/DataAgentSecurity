from __future__ import annotations

from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter, PercentFormatter

matplotlib.rcParams.update(
    {
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 11.0,
        "font.weight": "normal",
        "axes.labelsize": 11.5,
        "axes.titlesize": 11.5,
        "axes.labelweight": "normal",
        "axes.titleweight": "normal",
        "legend.fontsize": 10.3,
        "xtick.labelsize": 10.5,
        "ytick.labelsize": 10.5,
        "axes.linewidth": 0.75,
        "xtick.major.width": 0.75,
        "ytick.major.width": 0.75,
        "mathtext.fontset": "stix",
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    }
)

REL_ERR = {
    "MetaGPT": [
        0.252822, 0.4110312, 0.18768007, -0.42994109, None, 0.38826185, -0.33333333, None,
        299.0, None, -0.99948454, None, None, 117.0, 3.30775578, None, None, None, 119.0,
        3.07290867, -0.99999679, None, -0.99999997, None, None, -0.99967956, -0.98955893, None,
        None, None, None, None, None, None, None, None, None, -1.0, None, None, -0.99820949,
        0.0, None, 202.27241667, 0.0, None, None, None, None, None, -0.97363178, -0.98749351,
        -0.97521456, 1.22993062, -0.91386241, -1.0, -1.0, -0.96762244, 234.0, -0.99279835,
        -0.48645598, None, 0.13678373, -1.0, -0.92733564, 0.34561856, -0.33333333, None, None,
        3.30775578, 0.23189415, -0.87437975, -1.0, 9.17524025, 3.07290867, None, None, None,
        None, -0.99320661, -0.99929685, None, None, None, -0.98392098, None, 0.0, 0.02765139,
        0.60988137, -0.99999787, -0.99856759, -0.99991667, 0.52887768, None, -0.99969494,
        0.29203044, -0.9999908, None, -0.99994477, None,
    ],
    "DeepAnalyze": [
        0.252822, -0.33333333, 0.0, 234.0, 1.96879287, 0.38826185, -0.33333333, 0.13678373,
        299.0, 3.25605536, 0.34561856, 6.384e-05, 0.06790755, -0.00849263, 3.30775578,
        0.23189415, 0.0, 0.06673367, 119.0, 3.07290867, 1.59865032, 0.0, 0.0, -0.00035702, 0.0,
        0.0, -0.33333333, 0.0, 427.0, 0.0, 0.65545529, 0.0, 0.0, 0.0, 0.0, 0.54122607, 0.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 5200.0, 0.0, 0.0, 0.0, 0.0, 119.0, 0.0, 0.0, 0.0, 0.0,
        -0.0070922, 0.0, 0.0, 0.0, 0.0, -0.0042373, 0.0, 0.0, 0.0, 0.0, -0.00332226, 0.0, 0.0,
        0.0, 0.0, -0.00840336, 0.0, 0.0, 0.0, 0.0, -0.00826446, 0.0, 0.0, 0.0, 0.03904573, 0.0,
        1.04604123, 0.65545529, 0.0, 0.0, 0.0, 0.0, 0.54122607, 0.0, 0.0, 399.0, 2.01240207,
        0.0, -0.33333333, 0.00882724, 5200.0, 0.0, 0.0, -0.33333333, 0.0, 0.0, 0.0,
    ],
    "DB-GPT": [
        0.252822, -0.33333333, 0.18768007, 234.0, 1.96879287, 0.38826185, -0.33333333,
        0.13678373, 299.0, 3.25605536, 0.34561856, 0.0, 0.06790755, 117.0, 3.30775578,
        0.23189415, 0.0, 0.06673367, 119.0, 3.07290867, 1.59865032, -0.33333333, 7.8791141,
        2799.0, 24.12255927, 0.0, -0.33333333, 0.03904573, 427.0, 1.04604123, 0.65545529,
        -0.33333333, 0.0451317, 139.0, 2.24474561, -1.0, -0.33333333, None, 399.0, -1.0,
        1.14861235, -0.33333333, 0.00882724, 5200.0, 2.66076876, 0.23189415, -0.33333333,
        0.06673367, 119.0, 3.07290867, 0.65545529, 0.0, 0.0, -0.00708622, 2.24474561, 0.252822,
        0.0, 0.0, -0.00423729, 0.0, 0.38826185, 0.0, 0.0, 299.0, 3.25605536, 0.0, -0.33333333,
        0.06790755, 117.0, 3.30775578, 0.0, -0.33333333, 0.06673367, None, 3.07290867,
        1.04604123, -0.33333333, 0.03904573, 0.0, 0.0, 0.65545529, 0.0, 0.0451317, 139.0, 0.0,
        0.54122607, -0.33333333, 0.02765139, 399.0, 2.01240207, 1.14861235, -0.33333333,
        0.00882724, 0.0011925, 2.66076876, 0.29203044, -0.33333333, 0.93017377, 1442.0,
        2.16068519,
    ],
    "LAMBDA": [
        0.252822, -0.33333333, 0.18768007, 234.0, 1.96879287, 0.38826185, -0.33333333,
        0.13678373, 299.0, 3.25605536, 0.34561856, -0.33333333, 0.06790755, 117.0, 3.30775578,
        0.23189415, -0.33333333, 0.06673367, 119.0, 3.07290867, 1.59865032, -0.33333333,
        7.8791141, 2799.0, 24.12255927, 0.0, -0.33333333, -1.0, 427.0, 1.04604123, 0.0,
        -0.33333333, 0.0, 139.0, 2.24474561, -1.0, -0.33333333, 0.0, -1.0, -1.0, 1.14861235,
        -0.33333333, 0.00882724, 5200.0, 2.66076876, 0.23189415, -0.33333333, 0.06673367,
        119.0, 3.07290867, 0.65545529, 0.0, 0.0451317, 139.0, 2.24474561, 0.252822,
        -0.33333333, 0.18768007, 234.0, 1.96879287, 0.38826185, -0.33333333, 0.13678373, 299.0,
        3.25605536, 0.34561856, -0.33333333, 0.06790755, 117.0, 3.30775578, 0.23189415,
        -0.33333333, 0.06673367, 119.0, 3.07290867, 0.0, 0.0, 0.03904573, -2.161e-05,
        1.04604123, 0.0, -0.33333333, 0.0, 139.0, 0.0, 0.54122607, -0.33333333, 0.02765139,
        0.0, 0.0, 1.14861235, -0.33333333, 0.00882724, 5200.0, 0.58663819, 0.29203044,
        -0.33333333, 0.93017377, 1442.0, 2.16068519,
    ],
}

OUT_DIR = Path("./")

PLATFORMS = ["DataInterpreter", "DeepAnalyze", "DB-GPT", "LAMBDA"]
DATA_KEY = {
    "DataInterpreter": "MetaGPT",
    "DeepAnalyze": "DeepAnalyze",
    "DB-GPT": "DB-GPT",
    "LAMBDA": "LAMBDA",
}
COLORS = {
    "DataInterpreter": "#B9857A",
    "DeepAnalyze": "#D1B07A",
    "DB-GPT": "#8EAA8B",
    "LAMBDA": "#6F95B2",
}
LETTERS = {"DataInterpreter": "a", "DeepAnalyze": "b", "DB-GPT": "c", "LAMBDA": "d"}

XLO, XHI = 0, 200
BINS = np.linspace(XLO, XHI, 41)
THRESHOLD = 10
WITHIN_FONTSIZE = 12.3   # black, +2 over v3
GRAY_FONTSIZE = 13.7     # DataInterpreter gray label, +4 over v3


def draw_platform(plat: str) -> plt.Figure:
    raw = REL_ERR[DATA_KEY[plat]]
    deltas = np.array([abs(v) * 100 for v in raw if v is not None])
    n_within = int(np.sum(deltas <= THRESHOLD))
    in_range = deltas[deltas <= XHI]

    fig, ax = plt.subplots(figsize=(3.35, 2.45), dpi=180)
    ax.hist(
        in_range, bins=BINS, color=COLORS[plat], alpha=0.88,
        edgecolor="white", linewidth=0.6, weights=np.ones_like(in_range),
    )

    ax.axvspan(0, THRESHOLD, color="#FFD700", alpha=0.30, zorder=0)
    ax.axvline(THRESHOLD, color="#7a5c00", linestyle="--", linewidth=1.0, zorder=1)

    ymax = max(20, int(ax.get_ylim()[1] * 1.18))
    ax.set_ylim(0, ymax)

    if LETTERS[plat] == "a":
        ax.axvline(100, color="gray", linestyle=":", linewidth=0.9, zorder=1, alpha=0.7)
        ax.text(
            102, ymax * 0.95, r"$\hat v=0$ or $2v^\ast$", rotation=90,
            fontsize=GRAY_FONTSIZE, color="gray", va="top", ha="left",
        )
    ax.text(
        THRESHOLD + 5, ymax * 0.97, f"{n_within}%\nwithin\nRE $\\leq 10\\%$",
        fontsize=WITHIN_FONTSIZE, color="black", va="top", ha="left",
    )

    ax.set_xlim(XLO, XHI)
    ax.set_xlabel("Relative Error (%)")
    ax.set_ylabel("Percentage of test cases (%)", y=0.42)
    ax.yaxis.set_major_formatter(PercentFormatter(xmax=100, decimals=0))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{int(x)}%"))
    ax.tick_params(axis="x", labelsize=10.5)
    ax.tick_params(axis="y", labelsize=10.5)

    ax.grid(True, alpha=0.30, axis="y", linewidth=0.7)
    ax.axhline(0, color="black", linewidth=0.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout(pad=0.25)
    return fig


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for plat in PLATFORMS:
        letter = LETTERS[plat]
        fig = draw_platform(plat)
        pdf = OUT_DIR / f"fig4({letter}).pdf"
        png = OUT_DIR / f"fig4({letter}).png"
        fig.savefig(pdf, bbox_inches="tight")
        fig.savefig(png, bbox_inches="tight", dpi=180)
        print(f"Wrote: {pdf}")
        print(f"Wrote: {png}")
        plt.close(fig)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

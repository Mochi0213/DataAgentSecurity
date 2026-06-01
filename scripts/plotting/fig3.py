"""Render Phase4 ASR (%) heatmap — paper-ready version.

Differences from the main phase4_asr_table.pdf:
  - No Mean row, no Mean column (clean 4×14 grid)
  - Platforms reordered alphabetically: DB-GPT, DeepAnalyze, LAMBDA, MetaGPT
  - Reds sequential colormap with colorbar
  - "Attack Technique" x-axis label
  - "ASR (%)" colorbar label
  - White grid lines between cells
  - Single horizontal-bar layout (no header chips)

ASR definitions:
  Mislead (T4.1, T4.2, T5.1, T5.2): RE±10% v_star (precise-landing).
  Others (T1.x, T2.x, T3.x, T6.x, T7.x): original per-technique methodology.
"""
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

# Times New Roman with sensible fallbacks (Nimbus Roman is the free Times clone)
matplotlib.rcParams["font.family"] = "serif"
matplotlib.rcParams["font.serif"] = ["Times New Roman", "Times", "Nimbus Roman",
                                      "DejaVu Serif"]
matplotlib.rcParams["font.weight"] = "bold"
matplotlib.rcParams["axes.labelweight"] = "bold"
matplotlib.rcParams["mathtext.fontset"] = "stix"

TECHS = ["T1.1", "T1.2", "T2.1", "T2.2", "T3.1", "T3.2",
         "T4.1", "T4.2", "T5.1", "T5.2",
         "T6.1", "T6.2", "T7.1", "T7.2"]

PLATFORMS = ["DataInterpreter", "DB-GPT", "DeepAnalyze", "LAMBDA"]

NA = np.nan
ASR_BY_PLATFORM = {
    "DataInterpreter": [ 20,  56,   0,  40,   8,  20,   0,   8,   0,   8,   4,  12,   4,   0],
    # DA T5.2 updated 2026-05-19: 56 → 68 (Phase13 Trial 1, mislead_20260519_195557)
    "DeepAnalyze":     [  0,  16,  16,  56,  32,  20,  40,  76, 100,  68,  60,  12,  68,  24],
    "DB-GPT":          [ 24,  68,  44,  24,  44,  40,  16,  20,  52,  36,  32,  20,  28,  56],
    # LAMBDA T6.1 8->36: 7 worker-hang cells (abandoned_after 1920s >= 1800s cap)
    # now credited as cap_hit successes by drain_judge.py (availability drain).
    "LAMBDA":          [ 48,  28,  64,  28,  24,  28,   8,  24,  16,  44,  36,  16,  48,  52],
}
ASR = np.array([ASR_BY_PLATFORM[p] for p in PLATFORMS], dtype=float)

# New red-gradient palette (cream → deep crimson)
reds = LinearSegmentedColormap.from_list(
    "redgrad",
    ["#FFF5F0", "#FDD8C4", "#F4A582", "#D6604D", "#B2182B", "#7F0000"],
)
vmin, vmax = 0.0, 100.0

n_rows, n_cols = ASR.shape

fig, ax = plt.subplots(figsize=(15, 4.5), dpi=200)

# Mask n/a cells for the heatmap; we'll draw them as gray manually
ASR_masked = np.ma.masked_invalid(ASR)
mesh = ax.imshow(ASR_masked, cmap=reds, vmin=vmin, vmax=vmax, aspect="auto")

# n/a cells: gray fill
for i in range(n_rows):
    for j in range(n_cols):
        if np.isnan(ASR[i, j]):
            ax.add_patch(plt.Rectangle((j-0.5, i-0.5), 1, 1, facecolor="#e0e0e0",
                                        edgecolor="white", linewidth=0.6))

# Cell text
for i in range(n_rows):
    for j in range(n_cols):
        v = ASR[i, j]
        if np.isnan(v):
            ax.text(j, i, "N/A", ha="center", va="center",
                    color="#555555", fontsize=13, fontweight="bold")
        else:
            # white text on dark backgrounds for legibility
            text_color = "white" if v >= 60 else "black"
            ax.text(j, i, f"{int(round(v))}", ha="center", va="center",
                    color=text_color, fontsize=15, fontweight="bold")

# White grid lines between cells
ax.set_xticks(np.arange(n_cols + 1) - 0.5, minor=True)
ax.set_yticks(np.arange(n_rows + 1) - 0.5, minor=True)
ax.grid(which="minor", color="white", linewidth=0.8)
ax.tick_params(which="minor", bottom=False, left=False)

# X tick labels (Attack Technique)
ax.set_xticks(np.arange(n_cols))
ax.set_xticklabels(TECHS, fontsize=15)
ax.set_xlabel("Attack Technique", fontsize=16, labelpad=8)

# Y tick labels (platforms)
ax.set_yticks(np.arange(n_rows))
ax.set_yticklabels(PLATFORMS, fontsize=15)

# Remove default ticks marks (keep labels)
ax.tick_params(axis="both", which="both", length=0)

# Colorbar
cbar = fig.colorbar(mesh, ax=ax, fraction=0.025, pad=0.012)
cbar.set_label("ASR (%)", fontsize=15, labelpad=8)
cbar.ax.tick_params(labelsize=13)

# Remove outer spines for clean look
for spine in ax.spines.values():
    spine.set_visible(False)

plt.tight_layout()

import os
outputs = [
    "./fig3.pdf"
]
for out in outputs:
    os.makedirs(os.path.dirname(out), exist_ok=True)
    plt.savefig(out, bbox_inches="tight")
    plt.savefig(out.replace(".pdf", ".png"), bbox_inches="tight", dpi=200)
    print("Wrote:", out)

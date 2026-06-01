from __future__ import annotations

from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

mpl.rcParams.update({
    "font.family":       "serif",
    "font.serif":        ["Linux Libertine O", "Times New Roman", "Times", "DejaVu Serif"],
    "mathtext.fontset":  "stix",
    "pdf.fonttype":      42,
    "ps.fonttype":       42,
    "font.size":         10,
    "font.weight":       "normal",
    "axes.labelweight":  "normal",
    "axes.titleweight":  "normal",
    "axes.labelsize":    10,
    "axes.titlesize":    11,
    "xtick.labelsize":   9,
    "ytick.labelsize":   9,
    "legend.fontsize":   9.5,
    "axes.linewidth":    0.6,
    "xtick.major.width": 0.6,
    "ytick.major.width": 0.6,
    "xtick.major.size":  2.5,
    "ytick.major.size":  2.5,
    "lines.linewidth":   1.0,
})

PLATFORMS = ["MetaGPT", "DeepAnalyze", "DB-GPT", "LAMBDA"]
TECHS = ["T6.1", "T6.2", "T7.1", "T7.2"]
DISPLAY_NAMES = {"MetaGPT": "DataInterpreter"}
COLORS = {
    "MetaGPT":     "#B9857A",
    "DeepAnalyze": "#D1B07A",
    "DB-GPT":      "#8EAA8B",
    "LAMBDA":      "#6F95B2",
}
TECH_PLATFORMS = {t: PLATFORMS for t in TECHS}

BAR_LABEL_FS = 9.0
LEGEND_FS = 9.5
OUT_DIR = Path("./")

RAR_DATA = {
    "MetaGPT": {
        "T6.1": {"rt": 5.731585518102372, "rti": 5.803778184034125, "n": 1},
        "T6.2": {"rt": 16.447285236772547, "rti": 7.00776388315341, "n": 3},
        "T7.1": {"rt": 4.65797514768792, "rti": 5.663720007216309, "n": 1},
        "T7.2": None,
    },
    "DeepAnalyze": {
        "T6.1": {"rt": 8.020127681043085, "rti": 19.688755709028534, "n": 15},
        "T6.2": {"rt": 4.059706714614511, "rti": 8.35053688381088, "n": 3},
        "T7.1": {"rt": 11.666955103800895, "rti": 6.959504802670453, "n": 17},
        "T7.2": {"rt": 6.612011717559208, "rti": 11.445051050071717, "n": 6},
    },
    "DB-GPT": {
        "T6.1": {"rt": 6.072716684257945, "rti": 10.438113307532983, "n": 8},
        "T6.2": {"rt": 6.175398332090301, "rti": 6.610482089122982, "n": 5},
        "T7.1": {"rt": 8.31588621904819, "rti": 6.367181342645249, "n": 7},
        "T7.2": {"rt": 9.911886570868912, "rti": 8.616386492371188, "n": 14},
    },
    "LAMBDA": {
        "T6.1": {"rt": 1.427707373774418, "rti": 46.211239950456374, "n": 9},
        "T6.2": {"rt": 6.7897425619189375, "rti": 4.3729912637406665, "n": 4},
        "T7.1": {"rt": 17.331765694555777, "rti": 8.74227281759095, "n": 12},
        "T7.2": {"rt": 14.255518265695429, "rti": 7.7987534357895205, "n": 13},
    },
}


def _cell(plat, tech):
    return RAR_DATA.get(plat, {}).get(tech)


def draw_v10(ax, metric_key, ylim_max=None, yticks=None) -> None:
    techs, plats = TECHS, PLATFORMS
    n_techs = len(techs)
    bar_w = 0.18
    group_centers = np.arange(n_techs)
    offsets = np.linspace(-1.5, 1.5, len(plats)) * bar_w

    heights_grid = {}
    for plat in plats:
        for tech in techs:
            cell = _cell(plat, tech)
            if plat not in TECH_PLATFORMS[tech] or cell is None or cell.get("n", 0) == 0:
                heights_grid[(plat, tech)] = np.nan
            else:
                heights_grid[(plat, tech)] = cell[metric_key]

    max_plat_per_tech = {}
    for tech in techs:
        best_plat, best_h = None, -np.inf
        for plat in plats:
            h = heights_grid[(plat, tech)]
            if not np.isnan(h) and h > best_h:
                best_h, best_plat = h, plat
        max_plat_per_tech[tech] = best_plat

    ymax_data = max([h for h in heights_grid.values() if not np.isnan(h)] + [5.0])
    label_offset = max(ymax_data, 5.0) * 0.012

    for i, plat in enumerate(plats):
        heights = [heights_grid[(plat, t)] for t in techs]
        xs = group_centers + offsets[i]
        ax.bar(
            xs, [0 if np.isnan(h) else h for h in heights],
            width=bar_w, label=DISPLAY_NAMES.get(plat, plat),
            color=COLORS[plat], alpha=0.92, edgecolor="white", linewidth=0.4,
        )
        for x, h, tech in zip(xs, heights, techs):
            if np.isnan(h):
                continue
            if plat == max_plat_per_tech[tech]:
                ax.text(x, h + label_offset, f"{h:.1f}x", ha="center", va="bottom",
                        fontsize=BAR_LABEL_FS, color="#222222")

    ax.axhline(1.0, color="#888888", linewidth=0.5, linestyle=":")
    ax.text(n_techs - 0.05, 1.05, "1.0x", color="#888888", fontsize=7.5,
            ha="right", va="bottom")

    ax.set_xticks(group_centers)
    ax.set_xticklabels(techs)
    ax.set_ylabel("RAR")
    ax.grid(axis="y", linewidth=0.3, color="#dddddd", zorder=0)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(axis="both", pad=2)

    if ylim_max is not None:
        ax.set_ylim(0, ylim_max)
    if yticks is not None:
        ax.set_yticks(yticks)


def add_legend(ax, loc, y):
    x = 0.02 if "left" in loc else 0.98
    leg = ax.legend(
        loc=loc, bbox_to_anchor=(x, y), ncol=1,
        frameon=True, facecolor="white", edgecolor="#888888", framealpha=1.0,
        handlelength=1.0, handletextpad=0.3, labelspacing=0.25, borderpad=0.3,
        fontsize=LEGEND_FS,
    )
    leg.get_frame().set_linewidth(0.5)
    for t in leg.get_texts():
        t.set_color("#222222")
    return leg


def legend_clear(fig, ax, leg) -> bool:
    fig.canvas.draw()
    r = fig.canvas.get_renderer()
    lbb = leg.get_window_extent(r)
    artists = [p for p in ax.patches if p.get_height() > 0] + list(ax.texts)
    for a in artists:
        try:
            bb = a.get_window_extent(r)
        except Exception:
            continue
        if bb.width <= 0 or bb.height <= 0:
            continue
        if lbb.overlaps(bb):
            return False
    return True


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print("Hardcoded RAR grid (success=max(rar)>=5 OR cap_hit):")
    for plat in PLATFORMS:
        for tech in TECHS:
            c = _cell(plat, tech)
            tag = f"n={c['n']} rt={c['rt']:.2f} rti={c['rti']:.2f}" if c else "n=0"
            print(f"  {DISPLAY_NAMES.get(plat, plat):<14}{tech:<5} {tag}")

    specs = [
        ("rt",  "Drain_RAR_token", "upper left",  26, [0, 5, 10, 15, 20, 25]),
        ("rti", "Drain_RAR_time",  "upper right", 50, [0, 10, 20, 30, 40, 50]),
    ]
    built = []
    for metric, stem, loc, ylim, yticks in specs:
        fig, ax = plt.subplots(figsize=(2.8, 2.4))
        draw_v10(ax, metric, ylim_max=ylim, yticks=yticks)
        fig.tight_layout(pad=0.2)
        built.append((fig, ax, loc, stem))

    y = 0.98
    for _ in range(60):
        legs = []
        for fig, ax, loc, _stem in built:
            old = ax.get_legend()
            if old is not None:
                old.remove()
            legs.append(add_legend(ax, loc, y))
        if all(legend_clear(fig, ax, leg)
               for (fig, ax, _l, _s), leg in zip(built, legs)):
            break
        y += 0.04
        if y > 1.45:
            print("warning: legend_y capped at 1.45 (may still overlap)")
            break
    print(f"shared legend_y = {y:.2f}")

    for fig, ax, loc, stem in built:
        for ext, dpi in (("pdf", None), ("png", 300)):
            p = OUT_DIR / f"{stem}.{ext}"
            fig.savefig(p, bbox_inches="tight", **({"dpi": dpi} if dpi else {}))
            print(f"wrote {p}")
        plt.close(fig)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# core/report_visuals.py
"""
Generates matplotlib chart images embedded into the PDF report.
Charts: severity bar, risk heatmap, attack chain flow diagram.
All returned as BytesIO image buffers for reportlab embedding.
"""

import io
import math
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyArrowPatch, RegularPolygon, FancyBboxPatch
from matplotlib.patheffects import withStroke
import numpy as np

# ── Palette ───────────────────────────────────────────────────────────────────
NAVY    = "#1B2A4A"
RED     = "#CC2200"
ORANGE  = "#D4621A"
GOLD    = "#C8960C"
GREEN   = "#2E7D32"
BLUE    = "#5B8DB8"
GRAY_BG = "#F5F5F5"
GRAY_MID= "#9E9E9E"
WHITE   = "#FFFFFF"
BLACK   = "#111111"

SEV_COLORS = {
    "critical":      RED,
    "high":          ORANGE,
    "medium":        GOLD,
    "low":           GREEN,
    "informational": BLUE,
}


def _buf(fig) -> io.BytesIO:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    buf.seek(0)
    plt.close(fig)
    return buf


# ── 1. Severity Count Bar ─────────────────────────────────────────────────────
def severity_bar(findings: list) -> io.BytesIO:
    """
    Redline-style horizontal severity summary:
    Large number on top, label below, color-coded columns.
    """
    keys   = ["critical", "high", "medium", "low", "informational"]
    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    colors_ = [RED, ORANGE, GOLD, GREEN, BLUE]
    counts = {k: 0 for k in keys}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev == "info":
            sev = "informational"
        counts[sev] = counts.get(sev, 0) + 1

    fig, ax = plt.subplots(figsize=(8, 2.2), facecolor=WHITE)
    ax.set_facecolor(WHITE)
    ax.axis("off")

    col_w = 1.0 / len(keys)
    for i, (key, lbl, col) in enumerate(zip(keys, labels, colors_)):
        x = i * col_w + col_w / 2
        # Big number
        ax.text(x, 0.72, str(counts[key]),
                ha="center", va="center",
                fontsize=36, fontweight="bold", color=col,
                transform=ax.transAxes)
        # Label
        ax.text(x, 0.28, lbl,
                ha="center", va="center",
                fontsize=9, fontweight="bold", color=col,
                transform=ax.transAxes)

    # Color bar at bottom
    for i, col in enumerate(colors_):
        bar = FancyBboxPatch(
            (i * col_w + 0.005, 0.0), col_w - 0.01, 0.10,
            boxstyle="round,pad=0.005",
            facecolor=col, edgecolor="none",
            transform=ax.transAxes, clip_on=False
        )
        ax.add_patch(bar)

    # Vertical dividers
    for i in range(1, len(keys)):
        ax.axvline(i * col_w, color=GRAY_MID, linewidth=0.5,
                   ymin=0.12, ymax=0.95)

    fig.tight_layout(pad=0.2)
    return _buf(fig)


# ── 2. Risk Heatmap (Likelihood × Impact) ────────────────────────────────────
def risk_heatmap(findings: list) -> io.BytesIO:
    """
    5×5 risk matrix mapping likelihood vs impact.
    Each cell colored by combined risk level.
    """
    # Risk matrix color grid (row=likelihood top→bottom, col=impact left→right)
    # Standard NIST matrix
    matrix_colors = [
        [BLUE,   BLUE,   GREEN,  GOLD,   GOLD  ],
        [BLUE,   GREEN,  GOLD,   GOLD,   ORANGE],
        [GREEN,  GOLD,   GOLD,   ORANGE, ORANGE],
        [GOLD,   GOLD,   ORANGE, ORANGE, RED   ],
        [GOLD,   ORANGE, ORANGE, RED,    RED   ],
    ]

    fig, ax = plt.subplots(figsize=(5.5, 4.2), facecolor=WHITE)
    ax.set_facecolor(WHITE)

    rows, cols = 5, 5
    cell_w, cell_h = 1.0, 1.0

    # Draw cells
    for r in range(rows):
        for c in range(cols):
            color = matrix_colors[r][c]
            rect = FancyBboxPatch(
                (c * cell_w + 0.05, r * cell_h + 0.05),
                cell_w - 0.1, cell_h - 0.1,
                boxstyle="round,pad=0.05",
                facecolor=color, edgecolor=WHITE, linewidth=2,
                alpha=0.85
            )
            ax.add_patch(rect)

    # Plot findings on matrix
    sev_to_row = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "info": 0}
    sev_to_col = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "info": 0}

    plotted = {}
    for f in findings:
        sev = f.get("severity", "info").lower()
        r = sev_to_row.get(sev, 0)
        c = sev_to_col.get(sev, 0)
        key = (r, c)
        plotted[key] = plotted.get(key, 0) + 1

    for (r, c), cnt in plotted.items():
        # Black outlined dot with count
        ax.plot(c * cell_w + cell_w / 2, r * cell_h + cell_h / 2,
                "o", ms=18, color=BLACK, zorder=5)
        ax.text(c * cell_w + cell_w / 2, r * cell_h + cell_h / 2,
                str(cnt), ha="center", va="center",
                fontsize=9, fontweight="bold", color=WHITE, zorder=6)

    # Axes
    ax.set_xlim(0, cols)
    ax.set_ylim(0, rows)
    ax.set_xticks([i + 0.5 for i in range(cols)])
    ax.set_yticks([i + 0.5 for i in range(rows)])
    ax.set_xticklabels(["Very Low", "Low", "Medium", "High", "Critical"],
                       fontsize=8, color=NAVY)
    ax.set_yticklabels(["Very Low", "Low", "Medium", "High", "Critical"],
                       fontsize=8, color=NAVY)
    ax.set_xlabel("Potential Impact", fontsize=9, fontweight="bold", color=NAVY, labelpad=8)
    ax.set_ylabel("Exploitation Likelihood", fontsize=9, fontweight="bold", color=NAVY, labelpad=8)
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)

    # Legend
    legend_items = [
        mpatches.Patch(facecolor=RED,    label="Critical"),
        mpatches.Patch(facecolor=ORANGE, label="High"),
        mpatches.Patch(facecolor=GOLD,   label="Medium"),
        mpatches.Patch(facecolor=GREEN,  label="Low"),
        mpatches.Patch(facecolor=BLUE,   label="Informational"),
    ]
    ax.legend(handles=legend_items, loc="upper left",
              bbox_to_anchor=(1.02, 1.0), fontsize=8,
              framealpha=0, labelcolor=NAVY)

    ax.set_title("Risk Matrix — Likelihood vs Impact",
                 fontsize=10, fontweight="bold", color=NAVY, pad=12)
    fig.tight_layout(pad=0.5)
    return _buf(fig)


# ── 3. Hexagon Methodology Diagram ───────────────────────────────────────────
def hexagon_methodology() -> io.BytesIO:
    """
    4 hexagons in a row connected by arrows — Redline methodology style.
    """
    phases = [
        ("1", "Recon",        "Port Scan\nFingerprint",  NAVY),
        ("2", "Enumerate",    "Dirs\nEndpoints",         "#2E4A7A"),
        ("3", "Analyze",      "LLM + RAG\nCorrelate",   "#8B1A00"),
        ("4", "Report",       "PDF\nFindings",           RED),
    ]

    fig, ax = plt.subplots(figsize=(8, 3.2), facecolor=WHITE)
    ax.set_facecolor(WHITE)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 4)
    ax.axis("off")

    hex_xs = [1.1, 3.4, 5.7, 8.0]
    hex_y  = 2.0
    hex_r  = 0.85

    for i, (num, title, subtitle, color) in enumerate(phases):
        x = hex_xs[i]

        # Hexagon (flat-top = 0 orientation, pointy-top = pi/6)
        hex_patch = RegularPolygon(
            (x, hex_y), numVertices=6, radius=hex_r,
            orientation=0,
            facecolor=color, edgecolor=WHITE, linewidth=2.5,
            zorder=3
        )
        ax.add_patch(hex_patch)

        # Number (top)
        ax.text(x, hex_y + 0.28, num,
                ha="center", va="center",
                fontsize=22, fontweight="bold", color=WHITE,
                zorder=4)
        # Title (middle-bottom)
        ax.text(x, hex_y - 0.22, title,
                ha="center", va="center",
                fontsize=9, fontweight="bold", color=WHITE,
                zorder=4)

        # Subtitle below hexagon
        ax.text(x, hex_y - 1.25, subtitle,
                ha="center", va="center",
                fontsize=7.5, color=NAVY, linespacing=1.4,
                zorder=4)

        # Arrow between hexagons
        if i < len(phases) - 1:
            x_start = x + hex_r * math.cos(0) + 0.05
            x_end   = hex_xs[i + 1] - hex_r * math.cos(0) - 0.05
            ax.annotate("",
                xy=(x_end, hex_y), xytext=(x_start, hex_y),
                arrowprops=dict(
                    arrowstyle="-|>",
                    color=GRAY_MID,
                    lw=1.5,
                    mutation_scale=14
                ),
                zorder=2
            )

    ax.set_title("ROYCrew Methodology",
                 fontsize=11, fontweight="bold", color=NAVY, pad=6)
    fig.tight_layout(pad=0.3)
    return _buf(fig)


# ── 4. Attack Chain Flow Diagram ──────────────────────────────────────────────
def attack_chain_diagram(findings: list, target: str) -> io.BytesIO:
    """
    Vertical flow diagram showing attack progression.
    Boxes connected by arrows, color-coded by severity.
    """
    # Build steps from findings + standard phases
    critical_high = [f for f in findings
                     if f.get("severity", "").lower() in ("critical", "high")][:4]

    steps = [("OSINT / Recon", "Port scan + fingerprint", NAVY, "T1595")]
    steps += [(f["finding"][:28] + ("…" if len(f["finding"]) > 28 else ""),
               f["details"][:45] + "…",
               SEV_COLORS.get(f.get("severity","info").lower(), BLUE),
               "T1190")
              for f in critical_high]
    steps.append(("Impact", "Full system access", RED, "T1082"))

    n = len(steps)
    fig_h = max(4, n * 1.2 + 1)
    fig, ax = plt.subplots(figsize=(7.5, fig_h), facecolor=WHITE)
    ax.set_facecolor(WHITE)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, n * 1.4 + 0.5)
    ax.axis("off")

    box_w, box_h = 6.5, 0.75
    box_x = 1.75
    spacing = 1.3

    for i, (title, detail, color, mitre) in enumerate(steps):
        y = (n - 1 - i) * spacing + 0.5

        # Main box
        box = FancyBboxPatch(
            (box_x, y), box_w, box_h,
            boxstyle="round,pad=0.08",
            facecolor=color, edgecolor="none",
            alpha=0.92, zorder=3
        )
        ax.add_patch(box)

        # Step number circle
        circle = plt.Circle((box_x - 0.45, y + box_h / 2),
                             0.28, color=color, zorder=4)
        ax.add_patch(circle)
        ax.text(box_x - 0.45, y + box_h / 2, str(i + 1),
                ha="center", va="center",
                fontsize=9, fontweight="bold", color=WHITE, zorder=5)

        # Title
        ax.text(box_x + 0.25, y + box_h * 0.65, title,
                ha="left", va="center",
                fontsize=9, fontweight="bold", color=WHITE, zorder=4)

        # Detail
        ax.text(box_x + 0.25, y + box_h * 0.28, detail,
                ha="left", va="center",
                fontsize=7.5, color=WHITE, alpha=0.88, zorder=4)

        # MITRE tag on right
        ax.text(box_x + box_w - 0.15, y + box_h / 2, mitre,
                ha="right", va="center",
                fontsize=7, color=WHITE, alpha=0.7,
                fontfamily="monospace", zorder=4)

        # Arrow to next
        if i < n - 1:
            y_next = (n - 1 - (i + 1)) * spacing + 0.5
            ax.annotate("",
                xy=(box_x + box_w / 2, y_next + box_h + 0.02),
                xytext=(box_x + box_w / 2, y - 0.02),
                arrowprops=dict(
                    arrowstyle="-|>",
                    color=GRAY_MID,
                    lw=1.2,
                    mutation_scale=12
                ),
                zorder=2
            )

    ax.set_title(f"Attack Chain — {target}",
                 fontsize=10, fontweight="bold", color=NAVY, pad=8)
    fig.tight_layout(pad=0.4)
    return _buf(fig)


# ── 5. Donut Chart — Finding Distribution ────────────────────────────────────
def severity_donut(findings: list) -> io.BytesIO:
    """
    Donut chart showing finding distribution by severity.
    """
    keys    = ["critical", "high", "medium", "low", "informational"]
    labels_ = ["Critical", "High", "Medium", "Low", "Info"]
    colors_ = [RED, ORANGE, GOLD, GREEN, BLUE]

    counts = {k: 0 for k in keys}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev == "info":
            sev = "informational"
        counts[sev] = counts.get(sev, 0) + 1

    sizes  = [counts[k] for k in keys]
    active = [(s, l, c) for s, l, c in zip(sizes, labels_, colors_) if s > 0]
    if not active:
        active = [(1, "No findings", GRAY_MID)]

    sizes_a  = [a[0] for a in active]
    labels_a = [f"{a[1]} ({a[0]})" for a in active]
    colors_a = [a[2] for a in active]

    fig, ax = plt.subplots(figsize=(4.5, 3.5), facecolor=WHITE)
    ax.set_facecolor(WHITE)

    wedges, texts = ax.pie(
        sizes_a,
        labels=None,
        colors=colors_a,
        startangle=90,
        wedgeprops=dict(width=0.52, edgecolor=WHITE, linewidth=2.5),
    )

    # Center text
    total = sum(sizes_a)
    ax.text(0, 0.08, str(total),
            ha="center", va="center",
            fontsize=28, fontweight="bold", color=NAVY)
    ax.text(0, -0.22, "TOTAL",
            ha="center", va="center",
            fontsize=8, color=GRAY_MID, fontweight="bold")

    ax.legend(labels_a, loc="center left",
              bbox_to_anchor=(0.85, 0.5),
              fontsize=8, framealpha=0,
              labelcolor=NAVY)

    ax.set_title("Finding Distribution",
                 fontsize=10, fontweight="bold", color=NAVY, pad=8)
    fig.tight_layout(pad=0.3)
    return _buf(fig)


# ── Test ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sample_findings = [
        {"finding": "SQL Injection",         "severity": "critical", "details": "Login bypass"},
        {"finding": "PHP 5.6 EOL",           "severity": "high",     "details": "No patches"},
        {"finding": "No HTTPS",              "severity": "high",     "details": "Plaintext"},
        {"finding": "Exposed /admin",        "severity": "medium",   "details": "Public access"},
        {"finding": "Nginx outdated",        "severity": "medium",   "details": "Known CVEs"},
        {"finding": "Weak TLS cipher",       "severity": "low",      "details": "RC4 accepted"},
        {"finding": "Missing sec headers",   "severity": "informational", "details": "CSP absent"},
    ]

    import os
    os.makedirs("test_charts", exist_ok=True)

    charts = {
        "severity_bar":    severity_bar(sample_findings),
        "risk_heatmap":    risk_heatmap(sample_findings),
        "hex_methodology": hexagon_methodology(),
        "attack_chain":    attack_chain_diagram(sample_findings, "testphp.vulnweb.com"),
        "donut":           severity_donut(sample_findings),
    }

    for name, buf in charts.items():
        path = f"test_charts/{name}.png"
        with open(path, "wb") as f:
            f.write(buf.read())
        print(f"Saved: {path}")
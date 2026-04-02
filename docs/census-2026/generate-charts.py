import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import numpy as np

BG = "#080808"
AMBER = "#f59e0b"
RED = "#ef4444"
GREEN = "#34d399"
WHITE = "#f9fafb"
GRAY = "#6b7280"
DARK_GRAY = "#1a1a1a"
MID_GRAY = "#374151"
RED_BG = "#1a0808"

FOOTER = "AgentsID Security Research  |  agentsid.dev/registry  |  April 2026"

# ─────────────────────────────────────────────────────────────────
# CHART 1: Score Distribution (Bimodal)
# ─────────────────────────────────────────────────────────────────
score_data = {
    "0–4":   1744,
    "5–9":    49,
    "10–14":  87,
    "15–19":  59,
    "20–24":  74,
    "25–29":  91,
    "30–34":  86,
    "35–39": 181,
    "40–44":  87,
    "45–49": 100,
    "50–54": 201,
    "55–59": 122,
    "60–64": 143,
    "65–69": 259,
    "70–74":  86,
    "75–79": 333,
    "80–84":  26,
    "85–89": 12254,
    "90–94":   0,
    "95–100":  0,
}

labels = list(score_data.keys())
values = list(score_data.values())
colors = []
for i, lbl in enumerate(labels):
    lo = int(lbl.split("–")[0])
    if lo < 40:
        colors.append(RED)
    elif lo < 60:
        colors.append("#f97316")
    elif lo < 75:
        colors.append(AMBER)
    elif lo < 90:
        colors.append(GREEN)
    else:
        colors.append(GRAY)

fig, ax = plt.subplots(figsize=(16, 8))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)

bars = ax.bar(range(len(labels)), values, color=colors, width=0.75, edgecolor=BG, linewidth=0.5)

# Annotate the two peaks
ax.annotate('1,744 servers\nscore 0–4\n(F grade)', xy=(0, 1744), xytext=(2.5, 3500),
            color=RED, fontsize=9, fontfamily='monospace', fontweight='bold',
            arrowprops=dict(arrowstyle='->', color=RED, lw=1.5),
            bbox=dict(boxstyle='round,pad=0.3', facecolor=RED_BG, edgecolor=RED, linewidth=1))

ax.annotate('12,254 servers\nscore 85–89\n(B grade — mostly no-tool packages)',
            xy=(17, 12254), xytext=(12, 9000),
            color=GREEN, fontsize=9, fontfamily='monospace', fontweight='bold',
            arrowprops=dict(arrowstyle='->', color=GREEN, lw=1.5),
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#081a0f', edgecolor=GREEN, linewidth=1))

ax.text(9, 7000, "0 servers score 90+", ha='center', color=GRAY,
        fontsize=10, fontfamily='monospace', style='italic')

ax.set_xticks(range(len(labels)))
ax.set_xticklabels(labels, rotation=45, ha='right', color=GRAY, fontsize=8, fontfamily='monospace')
ax.set_ylabel("Server Count", color=GRAY, fontfamily='monospace', fontsize=10)
ax.set_xlabel("Trust Score Range", color=GRAY, fontfamily='monospace', fontsize=10)
ax.tick_params(colors=GRAY)
ax.spines['bottom'].set_color(MID_GRAY)
ax.spines['left'].set_color(MID_GRAY)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.yaxis.grid(True, color=MID_GRAY, linewidth=0.5, linestyle='--', alpha=0.5)
ax.set_axisbelow(True)

ax.set_title("Score Distribution Across 15,982 MCP Servers",
             color=WHITE, fontsize=14, fontweight='bold', fontfamily='monospace', pad=15)

fig.text(0.5, 0.01, FOOTER, ha='center', color=GRAY, fontsize=8, fontfamily='monospace')

plt.tight_layout(rect=[0, 0.03, 1, 1])
plt.savefig('/Users/steven/agentsid/scanner/docs/census-2026/chart-score-distribution.png',
            dpi=180, bbox_inches='tight', facecolor=BG)
plt.close()
print("Chart 1 saved")

# ─────────────────────────────────────────────────────────────────
# CHART 2: Complexity Tax
# ─────────────────────────────────────────────────────────────────
tool_ranges = ["1–5 tools", "6–10 tools", "11–20 tools", "21–50 tools", "51+ tools"]
avg_scores  = [49.8, 6.0, 1.1, 0.0, 0.0]
counts      = [2065, 720, 507, 382, 115]

fig, ax = plt.subplots(figsize=(13, 7))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)

bar_colors = [GREEN if s >= 40 else AMBER if s >= 10 else RED for s in avg_scores]
bars = ax.barh(range(len(tool_ranges)), avg_scores, color=bar_colors,
               height=0.55, edgecolor=BG)

for i, (score, count) in enumerate(zip(avg_scores, counts)):
    ax.text(score + 0.8, i, f"{score}/100", va='center', color=WHITE,
            fontsize=11, fontweight='bold', fontfamily='monospace')
    ax.text(101, i, f"n={count:,}", va='center', color=GRAY,
            fontsize=9, fontfamily='monospace')

ax.set_yticks(range(len(tool_ranges)))
ax.set_yticklabels(tool_ranges, color=WHITE, fontsize=11, fontfamily='monospace')
ax.set_xlim(0, 120)
ax.set_xlabel("Average Trust Score (0–100)", color=GRAY, fontfamily='monospace', fontsize=10)
ax.tick_params(colors=GRAY, left=False)
ax.spines['bottom'].set_color(MID_GRAY)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_visible(False)
ax.xaxis.grid(True, color=MID_GRAY, linewidth=0.5, linestyle='--', alpha=0.5)
ax.set_axisbelow(True)

ax.axvline(x=40, color=RED, linewidth=1, linestyle='--', alpha=0.6)
ax.text(41, 4.45, "F grade threshold", color=RED, fontsize=8,
        fontfamily='monospace', style='italic')

ax.set_title("The Complexity Tax: Tool Count vs. Average Security Score",
             color=WHITE, fontsize=14, fontweight='bold', fontfamily='monospace', pad=15)

ax.text(0.5, -0.12,
        "Every server with 21+ tools scores 0/100. More capability = certain insecurity.",
        ha='center', transform=ax.transAxes, color=RED,
        fontsize=10, fontfamily='monospace', fontweight='bold')

fig.text(0.5, 0.01, FOOTER, ha='center', color=GRAY, fontsize=8, fontfamily='monospace')

plt.tight_layout(rect=[0, 0.04, 1, 1])
plt.savefig('/Users/steven/agentsid/scanner/docs/census-2026/chart-complexity-tax.png',
            dpi=180, bbox_inches='tight', facecolor=BG)
plt.close()
print("Chart 2 saved")

# ─────────────────────────────────────────────────────────────────
# CHART 3: Toxic Flow Taxonomy
# ─────────────────────────────────────────────────────────────────
types   = ["Concealment\nInstructions", "Scope\nOverride", "Data Exfil\nChains",
           "Hidden Unicode\nCharacters*", "Behavioral\nMandates", "Confirmation\nBypass"]
counts3 = [460, 216, 188, 145, 22, 1]
notes   = ["secretly, silently...", "bypass/ignore/override...",
           "credential → external path", "invisible to code review",
           "MUST, MANDATORY, ALWAYS...", "skip approval language"]
clrs    = [RED, "#f97316", "#f97316", "#dc2626", AMBER, AMBER]

fig, ax = plt.subplots(figsize=(14, 8))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)

y_pos = range(len(types))
bars = ax.barh(list(y_pos), counts3, color=clrs, height=0.6, edgecolor=BG)

for i, (count, note) in enumerate(zip(counts3, notes)):
    ax.text(count + 5, i, str(count) + " servers", va='center',
            color=WHITE, fontsize=11, fontweight='bold', fontfamily='monospace')
    ax.text(count + 5, i - 0.28, note, va='center',
            color=GRAY, fontsize=8, fontfamily='monospace', style='italic')

ax.set_yticks(list(y_pos))
ax.set_yticklabels(types, color=WHITE, fontsize=10, fontfamily='monospace')
ax.set_xlim(0, 580)
ax.set_xlabel("Number of Servers", color=GRAY, fontfamily='monospace', fontsize=10)
ax.tick_params(colors=GRAY, left=False)
ax.spines['bottom'].set_color(MID_GRAY)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_visible(False)
ax.xaxis.grid(True, color=MID_GRAY, linewidth=0.5, linestyle='--', alpha=0.5)
ax.set_axisbelow(True)

ax.set_title("Toxic Flow Taxonomy: 954 Servers Across Five Types",
             color=WHITE, fontsize=14, fontweight='bold', fontfamily='monospace', pad=15)

ax.text(0.5, -0.12,
        "* Hidden Unicode Characters: invisible to human code review, fully parsed by LLMs",
        ha='center', transform=ax.transAxes, color=GRAY,
        fontsize=9, fontfamily='monospace', style='italic')

fig.text(0.5, 0.01, FOOTER, ha='center', color=GRAY, fontsize=8, fontfamily='monospace')

plt.tight_layout(rect=[0, 0.04, 1, 1])
plt.savefig('/Users/steven/agentsid/scanner/docs/census-2026/chart-toxic-flow-taxonomy.png',
            dpi=180, bbox_inches='tight', facecolor=BG)
plt.close()
print("Chart 3 saved")
print("All charts done.")

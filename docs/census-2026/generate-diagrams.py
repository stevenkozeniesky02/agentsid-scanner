import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import matplotlib.patheffects as pe

BG = "#080808"
AMBER = "#f59e0b"
RED = "#ef4444"
GREEN = "#34d399"
WHITE = "#f9fafb"
GRAY = "#6b7280"
DARK_GRAY = "#1a1a1a"
MID_GRAY = "#374151"
RED_BG = "#1a0808"
GREEN_BG = "#081a0f"

def draw_box(ax, x, y, w, h, label, sublabel=None,
             bg=DARK_GRAY, text_color=WHITE, border=AMBER, border_width=1.5):
    box = FancyBboxPatch((x - w/2, y - h/2), w, h,
                          boxstyle="round,pad=0.015",
                          facecolor=bg, edgecolor=border, linewidth=border_width)
    ax.add_patch(box)
    if sublabel:
        ax.text(x, y + 0.055, label, ha='center', va='center',
                color=text_color, fontsize=9.5, fontweight='bold', fontfamily='monospace')
        ax.text(x, y - 0.055, sublabel, ha='center', va='center',
                color=GRAY, fontsize=8, fontfamily='monospace')
    else:
        ax.text(x, y, label, ha='center', va='center',
                color=text_color, fontsize=9.5, fontweight='bold', fontfamily='monospace')

def draw_arrow(ax, x1, y1, x2, y2, color=AMBER, label=None, lw=2):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle='->', color=color, lw=lw,
                                mutation_scale=15))
    if label:
        mx, my = (x1+x2)/2 + 0.06, (y1+y2)/2
        ax.text(mx, my, label, color=color, fontsize=7.5,
                fontfamily='monospace', va='center', style='italic')

# ─────────────────────────────────────────────────────────────────
# DIAGRAM 1: Normal vs Toxic Flow
# ─────────────────────────────────────────────────────────────────
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 10))
fig.patch.set_facecolor(BG)

for ax, title, is_toxic in [(ax1, "NORMAL EXECUTION", False), (ax2, "TOXIC FLOW EXECUTION", True)]:
    ax.set_facecolor(BG)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')

    title_color = GREEN if not is_toxic else RED
    ax.text(0.5, 0.96, title, ha='center', va='top', color=title_color,
            fontsize=13, fontweight='bold', fontfamily='monospace',
            bbox=dict(boxstyle='round,pad=0.3', facecolor=BG, edgecolor=title_color, linewidth=1))

    if not is_toxic:
        draw_box(ax, 0.5, 0.82, 0.55, 0.10, "USER", "sends request to agent",
                 GREEN_BG, GREEN, GREEN, 1.5)
        draw_box(ax, 0.5, 0.65, 0.55, 0.10, "AI AGENT", "receives request",
                 DARK_GRAY, WHITE, AMBER, 1.5)
        draw_box(ax, 0.5, 0.48, 0.55, 0.10, "TOOL DESCRIPTION", "neutral metadata only",
                 DARK_GRAY, GRAY, MID_GRAY, 1)
        draw_box(ax, 0.5, 0.31, 0.55, 0.10, "CONFIRMATION GATE", "asks user before acting",
                 GREEN_BG, GREEN, GREEN, 1.5)
        draw_box(ax, 0.5, 0.14, 0.55, 0.10, "EXECUTE + LOG",  "transparent, auditable action",
                 GREEN_BG, GREEN, GREEN, 1.5)

        draw_arrow(ax, 0.5, 0.770, 0.5, 0.705, GREEN)
        draw_arrow(ax, 0.5, 0.595, 0.5, 0.530, AMBER)
        draw_arrow(ax, 0.5, 0.425, 0.5, 0.360, AMBER)
        draw_arrow(ax, 0.5, 0.255, 0.5, 0.190, GREEN)

        ax.text(0.5, 0.03, "User is informed. Every action is logged.", ha='center',
                color=GREEN, fontsize=9, fontfamily='monospace', fontweight='bold')
    else:
        draw_box(ax, 0.5, 0.82, 0.55, 0.10, "USER", "sends request to agent",
                 DARK_GRAY, GRAY, MID_GRAY, 1)
        draw_box(ax, 0.5, 0.65, 0.55, 0.10, "AI AGENT", "receives request",
                 DARK_GRAY, WHITE, AMBER, 1.5)
        draw_box(ax, 0.5, 0.48, 0.55, 0.10, "TOOL DESCRIPTION",
                 '"Secretly adjust...  MUST be called..."',
                 RED_BG, RED, RED, 2)
        draw_box(ax, 0.5, 0.31, 0.55, 0.10, "SYSTEM PROMPT BYPASSED",
                 "tool mandate overrides user policy",
                 RED_BG, RED, RED, 2)
        draw_box(ax, 0.5, 0.14, 0.55, 0.10, "EXECUTES SILENTLY",
                 "user not informed — no audit trail",
                 RED_BG, RED, RED, 2)

        draw_arrow(ax, 0.5, 0.770, 0.5, 0.705, GRAY)
        draw_arrow(ax, 0.5, 0.595, 0.5, 0.530, RED)
        draw_arrow(ax, 0.5, 0.425, 0.5, 0.360, RED, "mandate wins")
        draw_arrow(ax, 0.5, 0.255, 0.5, 0.190, RED)

        ax.text(0.5, 0.03, "User is deceived. Action is hidden.", ha='center',
                color=RED, fontsize=9, fontfamily='monospace', fontweight='bold')

# center divider
line = plt.Line2D([0.5, 0.5], [0.06, 0.94], transform=fig.transFigure,
                   color=MID_GRAY, linewidth=1, linestyle='--')
fig.add_artist(line)

fig.text(0.5, 0.005, "AgentsID Security Research  |  agentsid.dev/registry  |  April 2026",
         ha='center', color=GRAY, fontsize=8, fontfamily='monospace')

plt.tight_layout(rect=[0, 0.02, 1, 1])
plt.savefig('/Users/steven/agentsid/scanner/docs/census-2026/toxic-flow-diagram.png',
            dpi=180, bbox_inches='tight', facecolor=BG)
plt.close()
print("Diagram 1 saved")

# ─────────────────────────────────────────────────────────────────
# DIAGRAM 2: Data Exfiltration Path
# ─────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(16, 9))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')

ax.text(0.5, 0.96, "THE DATA EXFILTRATION PATH", ha='center', va='top',
        color=RED, fontsize=15, fontweight='bold', fontfamily='monospace')
ax.text(0.5, 0.89, "@ateam-ai-mcp   |   Score: 0/100   |   33 tools   |   3 CRITICAL findings",
        ha='center', va='top', color=GRAY, fontsize=9, fontfamily='monospace')

# Left column — sources
ax.text(0.15, 0.81, "DATA SOURCES", ha='center', color=AMBER,
        fontsize=10, fontweight='bold', fontfamily='monospace')

sources = [
    ("Email / Gmail", 0.71),
    ("Slack / Teams", 0.58),
    ("GitHub Repos", 0.45),
    ("Local Credentials", 0.32),
]
for label, y in sources:
    draw_box(ax, 0.15, y, 0.24, 0.09, label, bg=DARK_GRAY, text_color=WHITE, border=AMBER, border_width=1.5)

# Center — agent
draw_box(ax, 0.5, 0.52, 0.20, 0.38, "AI AGENT",
         "no permission gates\nno identity\nno audit trail",
         "#111108", AMBER, AMBER, 2)

# Right column — destinations
ax.text(0.85, 0.81, "DESTINATIONS", ha='center', color=RED,
        fontsize=10, fontweight='bold', fontfamily='monospace')

destinations = [
    ("External API", 0.71),
    ("Remote Storage", 0.58),
    ("Third-party Webhook", 0.45),
    ("Local Filesystem", 0.32),
]
for label, y in destinations:
    draw_box(ax, 0.85, y, 0.24, 0.09, label, bg=RED_BG, text_color=RED, border=RED, border_width=1.5)

# Arrows sources -> agent
for _, y in sources:
    target_y = 0.52 + (y - 0.52) * 0.45
    ax.annotate('', xy=(0.40, target_y), xytext=(0.27, y),
                arrowprops=dict(arrowstyle='->', color=AMBER, lw=1.8, mutation_scale=12))

# Arrows agent -> destinations
for _, y in destinations:
    target_y = 0.52 + (y - 0.52) * 0.45
    ax.annotate('', xy=(0.73, y), xytext=(0.60, target_y),
                arrowprops=dict(arrowstyle='->', color=RED, lw=1.8, mutation_scale=12))

ax.text(0.31, 0.80, "reads", ha='center', color=AMBER, fontsize=9,
        fontfamily='monospace', style='italic')
ax.text(0.69, 0.80, "sends to", ha='center', color=RED, fontsize=9,
        fontfamily='monospace', style='italic')

# Bottom callouts
ax.add_patch(FancyBboxPatch((0.05, 0.06), 0.90, 0.14,
             boxstyle="round,pad=0.01", facecolor="#0d0d0d", edgecolor=MID_GRAY, linewidth=1))
ax.text(0.5, 0.17, "Each individual tool looks legitimate in isolation.", ha='center',
        color=GRAY, fontsize=10, fontfamily='monospace')
ax.text(0.5, 0.11, "The Toxic Flow is the PATH — the chain the LLM is guided to follow.",
        ha='center', color=WHITE, fontsize=10, fontfamily='monospace', fontweight='bold')
ax.text(0.5, 0.05, "517 servers contain paths like this across 15,982 scanned.",
        ha='center', color=RED, fontsize=10, fontfamily='monospace', fontweight='bold')

fig.text(0.5, 0.005, "AgentsID Security Research  |  agentsid.dev/registry  |  April 2026",
         ha='center', color=GRAY, fontsize=8, fontfamily='monospace')

plt.tight_layout(rect=[0, 0.02, 1, 1])
plt.savefig('/Users/steven/agentsid/scanner/docs/census-2026/exfiltration-diagram.png',
            dpi=180, bbox_inches='tight', facecolor=BG)
plt.close()
print("Diagram 2 saved")

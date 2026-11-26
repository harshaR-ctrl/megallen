# Console UI layout

Layout reference for the analyst console (`web/index.html` + `web/style.css`). It describes where things sit and how
the page reflows; it does not repeat what the numbers mean (see `README.md`).

- **Stack:** plain HTML/CSS/JS, no build step. One page, four views toggled with the `.on` class (`.view { display: none }`,
  `.view.on { display: block }`).
- **Width:** `main` is centered, `max-width: 1680px`, padding `18px 24px 48px`.
- **Theme:** dark, defined once as CSS variables (`--surface`, `--line`, `--blue`, verdict colours `--v-*`). Cards are
  the only raised surface.

## Page shell (fixed order, every view)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ HEADER .topbar  (sticky, z-index 30)                                         │
│  [logo] Megallen      Model [select]   [Play][Reset] Speed[select] ▬▬▬ 40%   │
│                                 ...spacer...   [x] Hide IPs  ● Live  [Help]  │
├──────────────────────────────────────────────────────────────────────────────┤
│ TABS .tabs  Live monitor │ Alerts (3) │ How it decides │ Model results   ctx │
├──────────────────────────────────────────────────────────────────────────────┤
│ DATA STRIP .datastrip  "Data: …" "Zero-day: …"                    [Help]    │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  MAIN #main  →  exactly one <section class="view">                           │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

- **`.topbar`** is a wrapping flex row: brand, model select, replay group (play/pause, reset, speed, progress bar,
  progress text), a flexible `.spacer`, then right-side controls (mask toggle, connection status, help). Sticky under the
  viewport top with a translucent blurred background.
- **`.tabs`** is a horizontal tab list with the unreviewed-alert `.count` badge; `.ctx` (hidden model name + alert line)
  is pushed right with `margin-left: auto`.
- **`.datastrip`** is a full-bleed note row (dataset, hidden holdout, help button). It scrolls away with the page.
- **Overlays** sit outside `main`: `#helpdlg` (native `<dialog>`), `#tip` (fixed tooltip, z-index 60), `#toasts`
  (fixed stack, bottom-right), `.skip` link (kicker for keyboard users).

### Depth / stacking

| Layer | Element | z-index |
|---|---|---|
| Skip link on focus | `.skip` | 100 |
| Tooltip | `#tip` | 60 |
| Toasts | `#toasts` | 50 |
| Sticky header | `.topbar` | 30 |
| Sticky table head | `.tbl th` | 1 |
| Page content | `main`, cards | auto |

## Grid system

Two reusable grids carry almost the whole console:

| Class | Columns | Use |
|---|---|---|
| `.grid` | `repeat(3, minmax(0, 1fr))`, gap `14px` | Monitor dashboard |
| `.grid.two` | `repeat(2, minmax(0, 1fr))`, gap `14px` | How-it-decides, Model results |
| `.kpis` | `repeat(7, minmax(0,1fr))` (default) or `.kpis.four` = 4 | KPI strips |
| `.split` | `minmax(0, 1.3fr) minmax(400px, 1fr)`, gap `14px`, `align-items: start` | Alerts: table + detail |
| `.intro` | `minmax(0,1fr) minmax(0,1.25fr)` | Getting-started card |
| `.pipe` | `repeat(5, minmax(0,1fr))` | Decision pipeline strip |

`.span2` makes a card span two columns; `.card` is always `min-width: 0` so long content cannot blow out the grid.

## View 1 — Live monitor

```
┌ GETTING STARTED .intro ──────────────────────────────────────────────── × ┐
│ Catch traffic that matches no known attack   1 Play traffic → [button]     │
│ Every flow is checked by two models…         2 Send zero-day → [button]    │
│                                              3 See why        → [button]   │
├─ KPI ROW .kpis.four ──────────────────────────────────────────────────────┤
│ Connections checked │ Possible zero-days │ Known attacks │ Needs a look   │
├─ .grid (3 cols) ──────────────────────────────────────────────────────────┤
│ ┌────────── span2 ──────────┐ ┌──────── Possible zero-days ────────┐      │
│ │ Alerts in last 3 minutes  │ │ [Sent by you | All]   feed list    │      │
│ │ Plotly line chart, 340px  │ │ (spans 2 rows, scrolls, 600px max) │      │
│ └───────────────────────────┘ │                                    │      │
│ ┌────────── span2 ──────────┐ │                                    │      │
│ │ What the system decided   │ └────────────────────────────────────┘      │
│ │ bar rows per verdict      │ ┌──── Send traffic (sim-card) ───────┐      │
│ └───────────────────────────┘ │ count · Normal / Zero-day · attack │      │
│ ┌────────── span2 ──────────┐ │ select · mix · stress tests        │      │
│ │ Traffic shift (drift)     │ └────────────────────────────────────┘      │
│ └───────────────────────────┘                                             │
└───────────────────────────────────────────────────────────────────────────┘
```

- Order in the DOM is: chart (`span2`) → feed (1 col, `grid-row: span 2`) → verdict mix (`span2`) → simulate card →
  drift (`span2`). The feed therefore stands tall on the right for the first two rows, and Simulate drops beneath it.
- The KPI row is clickable: each KPI filters the Alerts view to its verdicts.
- Charts are Plotly and must keep an explicit height (`#chart-stream` is `340px`); the rest use the plain `.bars`
  bar-row component, not charts.

## View 2 — Alerts

```
┌ TOOLBAR .toolbar (wraps, aligned to bottom) ─────────────────────────────────┐
│ Verdict [chips…]   Source[▾]   Review status[▾]   Search[________]  [x] Keep │
├ .split ──────────────────────────────────────────────────────────────────────┤
│ ┌ Table, 1.3fr, scrolls, max-height calc(100vh - 230px) ┐ ┌ Detail aside ──┐ │
│ │ sticky header: Flow Time Verdict Best match Flow       │ │ sticky,        │ │
│ │ Unusualness Urgency What was sent Review               │ │ top 124px,     │ │
│ │ … rows …                                               │ │ own scroll     │ │
│ └────────────────────────────────────────────────────────┘ └────────────────┘ │
│ Keyboard hint line (j/k, i, e, r, f, /)                                       │
└───────────────────────────────────────────────────────────────────────────────┘
```

- Selecting a row loads the detail pane and keeps it in view. The table header is sticky **inside** the scrolling
  table card, so the filter bar stays put while rows scroll.
- The detail aside is a vertical stack: verdict header → sub-line → **Flow features** → **In short** (the two-question
  path + one-sentence summary) → **The checks in detail** (unusualness gauge, per-class score bars, rule table) →
  **What made it unusual** → **Your review** (action buttons + note) → collapsible JSON.
- Below ~1280px the split collapses to one column and the detail pane becomes a normal block beneath the table.

## View 3 — How it decides

```
┌ HERO card ────────────────────────────────────────────────────────────┐
│ How every flow gets its verdict                                       │
│ One lead paragraph                                                    │
│ [Input check] → [Novelty gate] → [Classifier] → [Conformal] → [Rules] │
└───────────────────────────────────────────────────────────────────────┘
┌ .grid.two ────────────────────────────────────────────────────────────┐
│ The decision rules (7 rows)   │ Confidence bars per class (table)     │
│ Top features by |SHAP| (bars) │ Glossary (term / definition)          │
└───────────────────────────────────────────────────────────────────────┘
```

- The pipeline is five equal `.pnode` boxes joined by CSS arrows; under 1280px it stacks vertically and the arrows
  rotate to point down.
- The glossary is a two-column `dl` (`150px 1fr`) that collapses to a single column on phones.

## View 4 — Model results

```
┌ Full-width card: every trained model on its test data ─ scrolls sideways ┐
├ KPI strip (default 7-up) ────────────────────────────────────────────────┤
┌ .grid.two ───────────────────────────────────────────────────────────────┐
│ Recognition per traffic type │ Outcome per traffic type                  │
│ Leakage checks               │ Speed on this machine (key/value)         │
└──────────────────────────────────────────────────────────────────────────┘
```

- The comparison table is the only wide table; it lives in a `.table-scroll` wrapper so it can overflow horizontally
  without widening the page. Clicking a row switches the console's active model.

## Responsive behaviour

| Breakpoint | Change |
|---|---|
| `> 1280px` | Full 3-column monitor, 7-up KPIs, side-by-side alerts split and sticky detail |
| `≤ 1280px` | KPIs → 4-up; `.grid` → 2 columns and `.feed-card` stops spanning rows; `.split` → 1 column with a static detail pane; `.intro` → 1 column; `.pipe` → vertical |
| `≤ 900px` | Drift card's two panels (verdict side / "what changed most") stack |
| `≤ 720px` | All grids, `.grid.two`, `.span2` and drift collapse to one column; `main` padding tightens; top bar/tabs padding tightens; `.ctx` hides; Simulate and glossary go single-column |

`prefers-reduced-motion: reduce` disables all animations and transitions.

## Content rules that affect layout

- **Everything is text-node built** (`h()` / `put()` in `app.js`), never `innerHTML` with event data. Nothing in the
  layout relies on injected markup.
- **Long values truncate** in table cells (`max-width: 240px; text-overflow: ellipsis`); the "what was sent" column is
  exempt. Flow-feature strings wrap in the detail pane instead.
- **Empty states are designed slots**, not blank cards: feed, verdict mix, table and detail each render a short
  headline + guidance + one primary action (`.empty`).
- **Tappable targets** are at least 40px tall (`.btn`, `.chip`); tab order follows DOM order, and every icon-only
  control has an `aria-label`.

# Console UI design

Visual design spec for the analyst console (`web/index.html` + `web/style.css`). It covers **how things look**:
colour, type, spacing, components, charts and states. Where things sit and how the page reflows is in `layout.md`;
this file follows the same structure and class names so the two can be read side by side.

## Design principles

1. **Charcoal, not pure black.** The base is a warm-neutral charcoal (`#121316`). Pure `#000` makes borders vanish
   and text glow. Charcoal keeps the layers readable.
2. **Flat. No gradients, no glows, no drop shadows on cards.** Depth comes from three surface steps plus 1px
   borders. The only shadow in the product is on floating overlays (tooltip, toasts, dialog).
3. **Colour carries meaning.** The chrome is greyscale plus one blue accent. Saturated colour is kept for
   verdicts and data, so a red pixel always means "possible zero-day" and nothing else.
4. **The chart is the brightest thing on the page.** Cards and grids stay low-contrast so the data lines read
   first.
5. **Every pairing meets WCAG AA.** All the text and verdict colours below were measured against all three
   surfaces (see the [contrast table](#contrast-checked)).

---

## 1. Colour tokens

Define these once in `:root`. Components never use raw hex values.

### Surfaces and lines

| Token | Hex | Use |
|---|---|---|
| `--bg` | `#121316` | Page background (charcoal black) |
| `--bg-sunken` | `#0e0f11` | Inset wells: inputs, gauge track, code/JSON block, table-scroll gutter |
| `--surface` | `#1a1c20` | Cards, the only raised surface |
| `--surface-2` | `#22252a` | Hover rows, active tab, chip resting state, select menus |
| `--surface-3` | `#2a2e34` | Pressed state, selected table row base, tooltip |
| `--line` | `#2c3036` | Card borders, table row dividers, chart grid |
| `--line-strong` | `#3d424a` | Input borders, hover borders, chart axis line |
| `--topbar-bg` | `rgba(18, 19, 22, 0.82)` | Sticky header, plus `backdrop-filter: blur(10px)` |

### Text

| Token | Hex | Use |
|---|---|---|
| `--text` | `#e8eaed` | Headings, values, primary text |
| `--text-2` | `#a8aeb7` | Body copy, table cells, labels |
| `--text-3` | `#868d97` | Meta, captions, axis ticks, placeholders, keyboard hints |
| `--text-on-accent` | `#0b0c0e` | Text on filled blue buttons |

### Accent (interface only, never data)

| Token | Hex | Use |
|---|---|---|
| `--blue` | `#4ea1ff` | Primary buttons, active tab underline, links, focus ring, progress bar fill |
| `--blue-hover` | `#6db2ff` | Primary button hover |
| `--blue-soft` | `rgba(78, 161, 255, 0.14)` | Selected row tint, active chip fill, "Sent by you" toggle |

### Verdict colours (`--v-*`)

These five are the only saturated colours. Each has a solid tone for text, dots and lines, and a *soft* tone
(the same hue at 14% alpha) for badge and row fills. All of them are flat, solid fills.

| Verdict | Token | Solid | Soft (`--v-*-soft`) | Meaning |
|---|---|---|---|---|
| Possible zero-day | `--v-zeroday` | `#ff5c73` | `rgba(255, 92, 115, 0.14)` | Novel traffic; the headline signal |
| Known attack | `--v-known` | `#f0883e` | `rgba(240, 136, 62, 0.14)` | Matched a trained attack class |
| Needs a look | `--v-review` | `#a88bfa` | `rgba(168, 139, 250, 0.14)` | Conformal set ambiguous or a rule fired |
| Normal | `--v-normal` | `#3fb984` | `rgba(63, 185, 132, 0.14)` | Benign |
| Invalid input | `--v-invalid` | `#8b949e` | `rgba(139, 148, 158, 0.14)` | Failed the input check |

Why these hues: red-rose, orange, violet, green and grey sit far apart on the colour wheel, so they stay
distinct for most colour-vision types. Verdicts are **never shown by colour alone**. Each badge also carries its
label, and each chart series has its own dash pattern (see §6).

### Status

| Token | Hex | Use |
|---|---|---|
| `--ok` | `#3fb984` | "● Live" dot (shares the normal green) |
| `--warn` | `#e6b450` | Reconnecting dot, drift warning text |
| `--err` | `#ff5c73` | Disconnected dot, error toasts |

```css
:root {
  --bg: #121316;        --bg-sunken: #0e0f11;
  --surface: #1a1c20;   --surface-2: #22252a;   --surface-3: #2a2e34;
  --line: #2c3036;      --line-strong: #3d424a;
  --text: #e8eaed;      --text-2: #a8aeb7;      --text-3: #868d97;  --text-on-accent: #0b0c0e;
  --blue: #4ea1ff;      --blue-hover: #6db2ff;  --blue-soft: rgba(78,161,255,.14);
  --v-zeroday: #ff5c73; --v-zeroday-soft: rgba(255,92,115,.14);
  --v-known:   #f0883e; --v-known-soft:   rgba(240,136,62,.14);
  --v-review:  #a88bfa; --v-review-soft:  rgba(168,139,250,.14);
  --v-normal:  #3fb984; --v-normal-soft:  rgba(63,185,132,.14);
  --v-invalid: #8b949e; --v-invalid-soft: rgba(139,148,158,.14);
  --ok: #3fb984; --warn: #e6b450; --err: #ff5c73;
  --topbar-bg: rgba(18,19,22,.82);
  color-scheme: dark;
}
```

### Contrast (checked)

The table gives WCAG contrast ratios against each surface. AA requires 4.5:1 for body text and 3:1 for large
text and UI parts.

| Colour | on `--bg` | on `--surface` | on `--surface-2` |
|---|---|---|---|
| `--text` | 15.4 | 14.2 | 12.8 |
| `--text-2` | 8.3 | 7.6 | 6.9 |
| `--text-3` | 5.6 | 5.1 | 4.6 |
| `--blue` | 7.0 | 6.4 | 5.8 |
| `--v-zeroday` | 6.2 | 5.7 | 5.2 |
| `--v-known` | 7.3 | 6.7 | 6.1 |
| `--v-review` | 6.9 | 6.3 | 5.7 |
| `--v-normal` | 7.5 | 6.9 | 6.2 |
| `--v-invalid` | 6.0 | 5.6 | 5.0 |
| `--text-on-accent` on `--blue` | | 7.3 | |

Rule: do not put `--text-3` on `--surface-3` or on any soft verdict fill. Use `--text-2` there.

---

## 2. Typography

| Role | Family |
|---|---|
| UI | `"Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif` |
| Data / mono | `"JetBrains Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace` |

Turn on `font-feature-settings: "tnum" 1, "cv11" 1;` for the whole UI so numbers line up in columns. Mono is
used for IPs, ports, flow IDs, feature strings, JSON and keyboard keys (`kbd`).

| Token | Size / line-height | Weight | Use |
|---|---|---|---|
| `--fs-kpi` | 28px / 32px | 600 | KPI values |
| `--fs-h1` | 20px / 28px | 600 | Hero title ("How every flow gets its verdict"), intro headline |
| `--fs-h2` | 15px / 22px | 600 | Card titles |
| `--fs-body` | 13.5px / 20px | 400 | Default text, table cells |
| `--fs-sm` | 12.5px / 18px | 400–500 | Labels, chips, tabs, toolbar labels |
| `--fs-xs` | 11px / 16px | 500 | Overlines, uppercase micro-labels (`letter-spacing: .06em`), axis ticks |

- Card titles use `--text` at 600. Their sub-captions use `--text-3` at `--fs-sm`.
- KPI labels are `--fs-xs`, uppercase, `--text-3`. KPI values are `--fs-kpi`, `--text`. Only the "Possible
  zero-days" value is coloured `--v-zeroday`, and only when it is above zero.
- Never set weights above 600. Avoid italics except in glossary terms.

---

## 3. Spacing, radius and borders

- **Spacing scale (4px base):** `4, 8, 12, 14, 16, 20, 24, 32, 48`. The grid gap is `14px`, as in `layout.md`.
  Card padding is `16px 18px`. Card header to body is `12px`.
- **Radius:** `--r-sm: 6px` (chips, inputs, badges), `--r-md: 8px` (buttons), `--r-lg: 10px` (cards, dialog),
  `999px` (status dots, count badge, toggles).
- **Borders:** every card is `1px solid var(--line)`. Hover or active is `--line-strong`. There are no double
  borders: nested blocks inside a card use `--bg-sunken` fills or a top divider, never another bordered box.
- **Elevation:** cards have none. Overlays (`#tip`, `#toasts`, `#helpdlg`) use
  `0 8px 24px rgba(0,0,0,.45), 0 0 0 1px var(--line-strong)`.

---

## 4. Page shell

### `.topbar` (sticky, z-index 30)
- Background `--topbar-bg` with `backdrop-filter: blur(10px)`, bottom border `1px solid var(--line)`, height
  56px (wraps taller on narrow screens), padding `10px 24px`.
- **Brand:** a 22px logo mark, solid `--blue` on `--surface-2` in a rounded square, plus "Megallen" at 15px/600 in
  `--text`.
- **Model select:** label `--text-3` `--fs-sm`, then a select styled as in §5.
- **Replay group:** Play/Pause is a primary button; Reset is a ghost button; Speed is a select. The progress bar
  is 120px × 4px on a `--bg-sunken` track with a solid `--blue` fill and `--r-full` ends. Next to it, the progress
  text is in mono `--fs-sm` `--text-2`.
- **Right side:** "Hide IPs" toggle switch (§5) · status pill (`● Live`: 8px dot in `--ok` with a 1.6s opacity
  pulse, `--fs-sm` `--text-2`) · Help as an icon-only ghost button with `aria-label`.

### `.tabs`
- Background `--bg`, bottom border `--line`. Tabs are 44px tall with `14px` horizontal padding, in `--fs-sm`/500.
- Resting tab: `--text-2`. Hover: `--text`. Active: `--text` with a 2px `--blue` bottom bar inset over the border.
  There is no fill behind the active tab.
- The `.count` badge on Alerts is 18px tall, in `--r-full`, with background `--v-zeroday-soft`, text
  `--v-zeroday`, and `--fs-xs`/600. When the count is zero, hide the badge; don't show "0".
- `.ctx` (pushed right) is `--fs-sm` `--text-3`, with the model name in mono `--text-2`.

### `.datastrip`
- Full bleed, background `--bg`, bottom border `--line`, padding `8px 24px`, `--fs-sm`.
- "Data:" and "Zero-day:" labels are in `--text-3`; their values are in `--text-2`. The hidden-holdout attack name
  is shown in a neutral mono chip, never in verdict colour, because it is context, not a result.

---

## 5. Components

### Card (`.card`)
`background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px; min-width: 0;`
- The header row holds the title (`--fs-h2`) and optional right-aligned controls (segmented toggle, "View all"
  link).
- Hover on clickable cards: the border changes to `--line-strong`. Cards never lift or scale.

### Buttons (`.btn`, min-height 40px)
| Variant | Rest | Hover | Pressed |
|---|---|---|---|
| Primary | bg `--blue`, text `--text-on-accent`, 600 | `--blue-hover` | `translateY(1px)` |
| Secondary | bg `--surface-2`, border `--line-strong`, text `--text` | bg `--surface-3` | bg `--surface-3` |
| Ghost | transparent, text `--text-2` | bg `--surface-2`, text `--text` | bg `--surface-3` |
| Danger (Mark as attack) | bg `--v-zeroday-soft`, text `--v-zeroday`, border `rgba(255,92,115,.35)` | soft alpha → .22 | — |

Padding is `0 14px`, radius `--r-md`, text `--fs-sm`/500. Icons are 16px with an 8px gap. Disabled buttons use
`opacity .45` and `cursor: not-allowed`.

### Focus
For everything focusable: `outline: 2px solid var(--blue); outline-offset: 2px;`, shown only on
`:focus-visible`. The `.skip` link sits off-screen and slides to `top: 8px; left: 8px` on focus, styled as a
primary button.

### Chips (`.chip`, min-height 40px; the verdict filters in the toolbar)
- Rest: bg `--surface-2`, border `--line`, text `--text-2`, with a leading 8px dot in the verdict's solid colour.
- Selected: bg is the verdict's `-soft` tone, the border is the solid colour at 45% alpha, text `--text`, and
  `aria-pressed="true"`.
- Non-verdict chips (Source, etc.) use `--blue-soft` and `--blue` when selected.

### Verdict badge (`.badge`)
Inline, 22px tall, padding `0 8px`, radius `--r-sm`, `--fs-xs`/600. Fill is the soft tone; text and the 6px dot
are the solid tone. The label is always written out ("Zero-day", "Known", "Review", "Normal", "Invalid").

### Inputs, selects and search
Height 36px (toolbar) or 32px (topbar), bg `--bg-sunken`, border `1px solid var(--line-strong)`, radius
`--r-sm`, text `--text`, placeholder `--text-3`. On focus the border is `--blue` with the focus ring. The select
chevron is an inline SVG in `--text-3`. The search box has a 16px magnifier icon and a `/` `kbd` hint on the
right.

### Toggle switch (Hide IPs, Keep)
A 32×18 track: `--surface-3` when off and `--blue` when on, with a 14px knob in `--text`. The text label sits to
the right.

### Segmented control (feed "Sent by you | All")
The container is `--bg-sunken` with radius `--r-md` and 2px padding. The active segment is `--surface-3` with
`--text`; inactive segments are `--text-3`.

### KPI (`.kpis`)
Each KPI is a card with 14px padding: the label (overline) on top, the value below, and an optional delta line in
`--fs-xs` (`--text-3`, or a verdict colour when it matters). A 3px left border in the verdict colour ties the KPI
to its filter: Possible zero-days → `--v-zeroday`, Known attacks → `--v-known`, Needs a look → `--v-review`,
Connections checked → `--line-strong`. Clickable KPIs show the hover border and a `→` that appears on hover.

### Bar rows (`.bars`, verdict mix and SHAP features)
- Row height 28px with a 6px gap: label (`--fs-sm` `--text-2`, fixed 140px), track, then the value in mono
  `--fs-sm` `--text`, right-aligned.
- The track is `--bg-sunken`, 8px tall, radius 999px. The fill is solid: the verdict colour for the verdict mix,
  `--blue` for SHAP bars. There are no gradients and no striping.

### Table (`.tbl`)
- The header is sticky, bg `--surface` (opaque, so rows don't show through), `--fs-xs` uppercase `--text-3`,
  with a bottom border of `--line-strong`.
- Rows are 40px with dividers in `--line`. Hover: `--surface-2`. Selected: `--blue-soft` with a 2px `--blue`
  inset bar on the left edge.
- Unreviewed rows: the Review column shows a hollow 8px dot in `--text-3`. Reviewed rows show a check in
  `--v-normal`.
- Numeric columns (Unusualness, Urgency) are right-aligned mono. Urgency shows a 40px mini bar in the same style
  as `.bars`.
- Cells truncate with an ellipsis at 240px; the full value goes in a `title` and in the tooltip.

### Detail aside
- A card with its own scroll. Each section is separated by a `1px var(--line)` top border and `16px` of padding,
  and each section heading is an overline (`--fs-xs` uppercase `--text-3`).
- **Verdict header:** a 4px top border in the verdict colour across the card, then the verdict label in
  `--fs-h1` in the solid colour, with the flow ID in mono `--text-3` below it.
- **Flow features:** a two-column key/value grid with keys in `--text-3` and values in mono `--text`; values wrap.
- **In short:** the two-question path is shown as two inline steps with `✓`/`✗` icons in `--v-normal` and
  `--v-zeroday`, followed by the summary sentence in `--text` at `--fs-body`.
- **Unusualness gauge:** a 10px horizontal track in `--bg-sunken` with a solid fill whose colour follows the
  verdict. The threshold is drawn as a 2px `--text` tick with a `--fs-xs` label, and the score is shown in mono.
- **Per-class score bars:** `.bars`, with the top class filled in its colour and the rest in `--line-strong`.
- **Rule table:** a compact table with 32px rows; fired rules have a `--v-review` dot.
- **Your review:** a row of buttons (Confirm zero-day = danger, Known = secondary, False alarm = secondary) and a
  textarea in the input style, 80px tall.
- **JSON:** a `<details>` with a summary in `--text-2`, and a `--bg-sunken` body in 12px mono `--text-2`
  with radius `--r-sm` and a max height of 320px that scrolls.

### Pipeline (`.pipe` / `.pnode`)
Each node is a `--surface-2` box with a `--line` border, radius `--r-md` and 14px padding. It shows a step
number (overline, `--blue`), a title (`--fs-sm`/600 `--text`) and a one-line caption (`--fs-xs` `--text-3`).
Arrows are a 1px `--line-strong` line with a CSS chevron, and they point down when the pipeline stacks. The
Novelty gate node gets a 2px `--v-zeroday` top border, because that is where zero-days are caught.

### Glossary (`dl`)
`dt` is `--text`/600; `dd` is `--text-2`. Rows are separated by `--line`. Term column: 150px.

### Getting-started card (`.intro`)
Same as a card, with a 3px `--blue` left border. The three steps are numbered 24px circles (`--blue-soft` fill,
`--blue` digit), each followed by text and a secondary button. The × close button is a ghost icon button
in the top right.

### Simulate card (`.sim-card`)
A number input for the count, a segmented control for Normal / Zero-day (the Zero-day segment shows a
`--v-zeroday` dot), an attack select, a mix slider and a "Stress tests" ghost-button group. The primary button
"Send traffic" sits full-width at the bottom.

### Feed (`.feed-card`)
List items are 52px tall: verdict dot, a src→dst line in mono `--text-2` (masked when "Hide IPs" is on, as
`•••.•••.12.4`), a relative time on the right in `--text-3`, and the unusualness score as a badge. New items fade
in over 180ms with a 2px `--v-zeroday` left bar that fades out after 3s.

### Drift card
The two panels have a `--line` divider between them. The verdict side uses a large status word ("Stable" in
`--v-normal`, "Shifting" in `--warn`). "What changed most" is a `.bars` list in `--blue`.

### Overlays
- **Tooltip `#tip`:** bg `--surface-3`, border `--line-strong`, radius `--r-sm`, padding `6px 8px`, `--fs-xs`
  `--text`, max-width 280px, overlay shadow. It appears after 120ms with no animation beyond an opacity fade.
- **Toasts `#toasts`:** 320px wide, bg `--surface-2`, overlay shadow, a 3px left border in the status or verdict
  colour, title `--text`/600, body `--text-2`. They auto-dismiss after 5s, and the close button keeps 40px of hit
  area.
- **Help dialog `#helpdlg`:** max-width 640px, bg `--surface`, radius `--r-lg`, overlay shadow.
  `::backdrop { background: rgba(8,9,10,.72); }` (a flat tint, no blur needed).

### Empty states (`.empty`)
Centred in the slot with 32px vertical padding: a 32px outline icon in `--text-3`, a headline in `--fs-h2`
`--text`, one line of guidance in `--text-2`, and one primary action. Never an empty card.

---

## 6. Charts (Plotly), made to stand out

The stream chart (`#chart-stream`, 340px) is the focal point. Its contrast comes from **bright, thick lines on a
quiet ground**, not from decoration.

### Rules
- The plot background is **transparent**, so it shows `--surface` underneath. The grid is `--line` at 1px,
  horizontal only. No vertical grid; no zero-line beyond the x-axis line.
- Lines are 2.5px `spline` with `smoothing: 0.6`. Markers are hidden except on hover. The **zero-day series is
  drawn last (on top) at 3px.**
- One flat, translucent area fill on the zero-day series only (`fill: 'tozeroy'`, `fillcolor` the soft tone at
  0.14). This is a single solid alpha fill, not a gradient, and it makes the series that matters read first.
- Each series gets its own dash so colour is never the only cue: zero-day solid, known `dot`, review `dash`,
  normal `longdash` at 1.75px and lower opacity (0.7) because normal traffic is context.
- Axis ticks: `--text-3` at 11px mono. Legend: horizontal, top-left, `--text-2` at 12px, with no background.
- Hover: `hovermode: 'x unified'`, with the label styled like `#tip`. The spike line is 1px `--line-strong`.
- When the alert threshold is shown, draw it as a horizontal `--text-3` dotted shape with a right-aligned
  `--fs-xs` annotation.

### Theme snippet

```js
const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

const SERIES = {
  zeroday: { color: css('--v-zeroday'), dash: 'solid',    width: 3,    fill: 'tozeroy', fillcolor: 'rgba(255,92,115,.14)' },
  known:   { color: css('--v-known'),   dash: 'dot',      width: 2.5 },
  review:  { color: css('--v-review'),  dash: 'dash',     width: 2.5 },
  normal:  { color: css('--v-normal'),  dash: 'longdash', width: 1.75, opacity: 0.7 },
};
// Draw order: normal → review → known → zeroday (zero-day on top).

const LAYOUT = {
  height: 340,
  margin: { l: 44, r: 16, t: 28, b: 36 },
  paper_bgcolor: 'rgba(0,0,0,0)',
  plot_bgcolor:  'rgba(0,0,0,0)',
  font: { family: 'Inter, system-ui, sans-serif', size: 12, color: css('--text-2') },
  xaxis: {
    showgrid: false, zeroline: false,
    linecolor: css('--line-strong'), tickcolor: css('--line-strong'),
    tickfont: { family: 'JetBrains Mono, monospace', size: 11, color: css('--text-3') },
    showspikes: true, spikemode: 'across', spikethickness: 1, spikecolor: css('--line-strong'), spikedash: 'solid',
  },
  yaxis: {
    gridcolor: css('--line'), gridwidth: 1, zeroline: false, rangemode: 'tozero',
    tickfont: { family: 'JetBrains Mono, monospace', size: 11, color: css('--text-3') },
  },
  legend: { orientation: 'h', x: 0, y: 1.12, font: { size: 12, color: css('--text-2') }, bgcolor: 'rgba(0,0,0,0)' },
  hovermode: 'x unified',
  hoverlabel: { bgcolor: css('--surface-3'), bordercolor: css('--line-strong'),
                font: { family: 'Inter, system-ui, sans-serif', size: 12, color: css('--text') } },
};

const CONFIG = { displayModeBar: false, responsive: true };

const trace = (key, x, y, name) => ({
  type: 'scatter', mode: 'lines', name, x, y,
  line: { color: SERIES[key].color, width: SERIES[key].width, dash: SERIES[key].dash, shape: 'spline', smoothing: 0.6 },
  opacity: SERIES[key].opacity ?? 1,
  fill: SERIES[key].fill ?? 'none', fillcolor: SERIES[key].fillcolor,
});
```

### Other data visuals
- **Model results tables:** the best value in each metric column is shown in `--text`/600 with a small `--blue`
  dot. Everything else is `--text-2`. No heatmap cell colouring.
- **Recognition / Outcome per traffic type:** `.bars`. Outcome uses stacked solid segments in verdict colours,
  separated by 2px gaps in `--surface` instead of borders.
- **Leakage checks:** a list with pass/fail icons in `--v-normal` and `--v-zeroday`, and the values in mono.
- **Speed (key/value):** keys in `--text-3`, values in mono `--text`, right-aligned.

---

## 7. Motion

- Durations: `120ms` for hover and colour, `180ms` for entering items, `240ms` for the detail pane swap. Easing:
  `cubic-bezier(.2,.7,.2,1)`.
- Animate only `opacity`, `transform` and `background-color`. Nothing bounces or scales on hover.
- The live dot pulses opacity between 1 and 0.45 over 1.6s.
- With `prefers-reduced-motion: reduce`, all transitions and animations are set to `0s` and the live dot holds
  steady.

---

## 8. Responsive visual tweaks

These sit on top of the breakpoints in `layout.md`:

| Breakpoint | Visual change |
|---|---|
| `≤ 1280px` | KPI value 24px. Pipeline arrows point down. |
| `≤ 900px` | The drift divider becomes horizontal. |
| `≤ 720px` | Card padding `14px`; `--fs-kpi` 22px; the chart drops to 280px with the legend under the plot (`y: -0.2`); tab text `--fs-xs`, scrollable with no visible scrollbar. |

---

## 9. Do / don't

| Do | Don't |
|---|---|
| Use the tokens; add a new token if something is missing | Hard-code hex values in components |
| Use solid fills and 1px borders | Use gradients, glows, neon shadows or glassmorphism on cards |
| Keep red-rose for zero-day only | Use `--v-zeroday` for generic errors next to verdict data (use the toast style instead) |
| Write verdict labels out next to their colour | Rely on colour alone |
| Use mono for IPs, IDs, numbers in tables | Use mono for prose |
| Keep the greyscale chrome quiet so the chart is the brightest thing | Add more accent colours to make the chrome "pop" |

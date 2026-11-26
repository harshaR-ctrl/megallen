# Colour palette: Megallen analyst console

This file is the single source of truth for every colour in the console. `design.md` says *where* each colour is
used; this file says *what the colours are*, why they were chosen, and how to use them safely.

**Character:** void black base, greyscale chrome, one acid-lime accent, five verdict colours. Every colour is a
flat, solid fill. There are no gradients and no glows.

---

## 1. Neutrals (the base)

The page is true black. Everything else steps up from it in small, even increments. Card fill is only a hair
lighter than the page (1.08:1), so **cards are defined by their 1px `--line` border**, not by their fill. That
gives the clean, OLED-style look: black space with thin outlined panels.

| Swatch | Token | Hex | RGB | Role |
|---|---|---|---|---|
| ⬛ | `--bg` | `#000000` | 0, 0, 0 | **Page background: void black** |
| ⬛ | `--bg-sunken` | `#050607` | 5, 6, 7 | Inset wells *inside cards*: inputs, bar and gauge tracks, JSON block |
| ⬛ | `--surface` | `#0C0D0F` | 12, 13, 15 | Cards, the only raised layer |
| ⬛ | `--surface-2` | `#15171A` | 21, 23, 26 | Hover rows, chips, active tab, menus, toasts |
| ⬛ | `--surface-3` | `#1D2024` | 29, 32, 36 | Pressed state, tooltip, selected row base |
| ▫️ | `--line` | `#24272C` | 36, 39, 44 | Card borders, row dividers, chart grid |
| ▫️ | `--line-strong` | `#363A41` | 54, 58, 65 | Input borders, hover borders, axis lines, overlay ring |

Above black, the neutrals have a very slight cool tint (blue is 3–11 points higher than red). This keeps the dark
greys from looking brown or olive next to the acid-lime accent. A warm or green-tinted grey would make the lime
look dirty.

**On void black, shadows do nothing.** Overlays (tooltip, toasts, dialog) are lifted by a lighter fill
(`--surface-2` or `--surface-3`) plus a 1px `--line-strong` ring.

### Text

| Swatch | Token | Hex | Role |
|---|---|---|---|
| ⬜ | `--text` | `#E8EAED` | Headings, values, primary text |
| ⬜ | `--text-2` | `#A8AEB7` | Body text, table cells, labels |
| ⬜ | `--text-3` | `#868D97` | Captions, meta, axis ticks, placeholders |
| ⬛ | `--text-on-accent` | `#0B0C0E` | Text on filled lime buttons |

The primary text is `#E8EAED`, not pure white `#FFFFFF`. Pure white on pure black is the harshest possible
pairing (21:1). It halates (text appears to bleed and blur) and tires the eyes over a long session. At 17.4:1,
`#E8EAED` is still crisp.

---

## 2. Accent (interface only)

| Swatch | Token | Hex | Role |
|---|---|---|---|
| 🟩 | `--lime` | `#C8FF00` | Primary buttons, active tab bar, links, focus ring, progress fill, Live dot, SHAP and drift bars |
| 🟩 | `--lime-hover` | `#D8FF4D` | Primary button hover |
| 🟩 | `--lime-press` | `#B4E600` | Primary button pressed |
| 🟩 | `--lime-soft` | `rgba(200, 255, 0, .12)` ≈ `#232A0D` on a card | Selected row, active non-verdict chip, logo tile |

Acid lime (`#C8FF00`, hue 73°) is the signature colour and the only colour on the chrome. On void black it is
very loud (17.8:1), so use it **sparingly**: one filled primary button per view, thin lines (2px tab bar, 2px
focus ring, 4px progress bar) and small dots. Large areas get `--lime-soft`, never solid lime.

Lime **never** represents a verdict or a series in the stream chart, so users never confuse "clickable" with a
result. Filled lime buttons always use dark text (`--text-on-accent`, 16.6:1), never white.

---

## 3. Verdict colours (data only)

These are the only saturated colours in the product. Each verdict has a **solid** tone (for text, dots, lines
and bar fills) and a **soft** tone (the same hue at 14% alpha, for badge and row backgrounds).

| Swatch | Verdict | Token | Solid | Soft (on a card) | Hue |
|---|---|---|---|---|---|
| 🟥 | **Possible zero-day** | `--v-zeroday` | `#FF5C73` | `#2E181D` | Red-rose, 352° |
| 🟧 | Known attack | `--v-known` | `#F0883E` | `#2C1E16` | Orange, 25° |
| 🟪 | Needs a look | `--v-review` | `#A88BFA` | `#221F30` | Violet, 255° |
| 🟦 | Normal | `--v-normal` | `#29B0C2` | `#102428` | Cyan, 187° |
| ⬜ | Invalid input | `--v-invalid` | `#8B949E` | `#1E2023` | Neutral grey |

**Why this set works**
- **Distinct hues.** The four coloured verdicts are spaced around the colour wheel (352° → 25° → 187° → 256°), so
  no two are neighbours. Red and orange are the closest pair, so they are also told apart by lightness and by
  chart dash style.
- **Clear of the accent.** Normal used to be green, which would blur into acid lime. It is now cyan (187°),
  about 115° from lime, so "safe traffic" and "clickable" never look alike. Warn amber (40°) sits between orange
  and lime but is used only for system status.
- **Similar brightness.** All five solids land between 6.3:1 and 7.7:1 contrast on a card, so none looks
  louder by accident. Zero-day gets its emphasis from line weight, fill and draw order, not from being brighter.
- **Severity reads naturally.** Warm colours (red, orange) are for attacks, cool violet is for "look at this",
  calm cyan is for safe, and grey is for "couldn't check".
- **Colour-vision safety.** Red against cyan is the pairing that survives protanopia and deuteranopia best, much
  better than red against green. Labels and dash patterns still always back up the colour.

### Status colours

| Swatch | Token | Hex | Role |
|---|---|---|---|
| 🟩 | `--ok` | `#C8FF00` | "● Live" dot (shares the accent lime) |
| 🟨 | `--warn` | `#E6B450` | Reconnecting, drift "Shifting" |
| 🟥 | `--err` | `#FF5C73` | Disconnected, error toasts |

`--warn` amber is used **only** for system status, never for a verdict, so it can't be confused with orange
"Known attack" in the data. The Live dot shares the lime accent because it is system chrome, not a result.

---

## 4. Chart palette

### Stream chart series (Plotly `colorway` order)

```js
colorway: ['#29B0C2', '#A88BFA', '#F0883E', '#FF5C73']  // normal → review → known → zero-day
```

The order is the draw order: the last series is drawn on top. Zero-day always comes last.

| Series | Colour | Line | Width | Opacity | Fill |
|---|---|---|---|---|---|
| Normal | `#29B0C2` | longdash | 1.75px | 0.7 | — |
| Needs a look | `#A88BFA` | dash | 2.5px | 1 | — |
| Known attack | `#F0883E` | dot | 2.5px | 1 | — |
| **Possible zero-day** | `#FF5C73` | solid | **3px** | 1 | `rgba(255,92,115,.14)` to zero (flat) |

### Chart chrome

| Part | Colour |
|---|---|
| Plot and paper background | `transparent` (the card `#0C0D0F` shows through) |
| Grid (horizontal only) | `#24272C` |
| Axis line, ticks, spike line | `#363A41` |
| Tick labels | `#868D97` |
| Legend text | `#A8AEB7` |
| Hover label | bg `#1D2024`, border `#363A41`, text `#E8EAED` |
| Threshold line | `#868D97`, dotted |

### Single-hue charts (no verdict meaning)
SHAP features, "what changed most" in the drift card, and the speed bars all use `--lime` `#C8FF00` on a
`#050607` track. If a chart needs more than one neutral series, use `#C8FF00`, then `#8B949E`, then `#363A41`.

---

## 5. Contrast (measured, WCAG)

AA requires 4.5:1 for normal text and 3:1 for large text and UI parts.

### Foregrounds on surfaces

| Colour | on `--bg` | on `--surface` | on `--surface-2` |
|---|---|---|---|
| `--text` `#E8EAED` | 17.4 | 16.1 | 14.9 |
| `--text-2` `#A8AEB7` | 9.4 | 8.7 | 8.0 |
| `--text-3` `#868D97` | 6.3 | 5.8 | 5.4 |
| `--lime` `#C8FF00` | 17.8 | 16.4 | 15.2 |
| `--lime-hover` `#D8FF4D` | 18.3 | 17.0 | 15.7 |
| `--lime-press` `#B4E600` | 14.3 | 13.2 | 12.2 |
| `--v-zeroday` `#FF5C73` | 7.0 | 6.5 | 6.0 |
| `--v-known` `#F0883E` | 8.3 | 7.7 | 7.1 |
| `--v-review` `#A88BFA` | 7.7 | 7.2 | 6.6 |
| `--v-normal` `#29B0C2` | 8.1 | 7.5 | 6.9 |
| `--v-invalid` `#8B949E` | 6.8 | 6.3 | 5.8 |
| `--warn` `#E6B450` | 11.0 | 10.2 | 9.4 |
| `--text-on-accent` on `--lime` | — | 16.6 | — |

`--text-3` on `--surface-3` measures 4.9, so it passes everywhere in the neutral stack.

### Badges (solid text on its own soft fill, over a card)

| Badge | Text colour | Ratio | Passes |
|---|---|---|---|
| Zero-day | `#FF5C73` on `#2E181D` | 5.56 | ✅ AA |
| Known | `#F0883E` on `#2C1E16` | 6.36 | ✅ AA |
| Needs a look | `#A88BFA` on `#221F30` | 5.92 | ✅ AA |
| Normal | `#29B0C2` on `#102428` | 6.19 | ✅ AA |
| Invalid | `#8B949E` on `#1E2023` | 5.31 | ✅ AA |
| Lime chip (selected) | `#C8FF00` on `#232A0D` | 12.6 | ✅ AAA |
| Any soft fill | `--text-2` `#A8AEB7` | 7.2–7.4 | ✅ AAA |
| Any soft fill | `--text` `#E8EAED` | 13.3–13.8 | ✅ AAA |

**Rules from these numbers**
1. Every badge can use its own solid colour for its label.
2. Keep `--text-3` off soft verdict fills. Use `--text-2` instead.
3. Selected table rows (`--lime-soft`) keep cell text at `--text` or `--text-2`.

---

## 6. State recipes

| State | Neutral element | Verdict element |
|---|---|---|
| Rest | bg `--surface-2`, border `--line` | bg soft, text solid |
| Hover | bg `--surface-3`, border `--line-strong` | soft alpha .14 → .22 |
| Selected / pressed | bg `--lime-soft` + 2px `--lime` edge | soft fill + border in solid at 45% alpha |
| Focus | `2px solid #C8FF00`, offset 2px | same |
| Disabled | `opacity: .45` | same |

---

## 7. Copy-paste exports

### CSS

```css
:root {
  color-scheme: dark;

  /* Neutrals */
  --bg-sunken:   #050607;
  --bg:          #000000;
  --surface:     #0C0D0F;
  --surface-2:   #15171A;
  --surface-3:   #1D2024;
  --line:        #24272C;
  --line-strong: #363A41;
  --topbar-bg:   rgba(0, 0, 0, .80);

  /* Text */
  --text:           #e8eaed;
  --text-2:         #a8aeb7;
  --text-3:         #868d97;
  --text-on-accent: #0b0c0e;

  /* Accent */
  --lime:       #c8ff00;
  --lime-hover: #d8ff4d;
  --lime-press: #b4e600;
  --lime-soft:  rgba(200, 255, 0, .12);

  /* Verdicts */
  --v-zeroday: #ff5c73;  --v-zeroday-soft: rgba(255, 92, 115, .14);
  --v-known:   #f0883e;  --v-known-soft:   rgba(240, 136, 62, .14);
  --v-review:  #a88bfa;  --v-review-soft:  rgba(168, 139, 250, .14);
  --v-normal:  #29b0c2;  --v-normal-soft:  rgba(41, 176, 194, .14);
  --v-invalid: #8b949e;  --v-invalid-soft: rgba(139, 148, 158, .14);

  /* Status */
  --ok:   #c8ff00;
  --warn: #e6b450;
  --err:  #ff5c73;

  /* Overlays */
  --shadow-overlay: 0 0 0 1px var(--line-strong), 0 12px 32px rgba(0, 0, 0, .6); /* ring does the work on black */
  --backdrop:       rgba(0, 0, 0, .75);
}
```

### JS (for Plotly and app.js)

```js
export const PALETTE = {
  bg: '#000000', bgSunken: '#050607',
  surface: '#0C0D0F', surface2: '#15171A', surface3: '#1D2024',
  line: '#24272C', lineStrong: '#363A41',
  text: '#e8eaed', text2: '#a8aeb7', text3: '#868d97',
  lime: '#c8ff00', limeHover: '#d8ff4d', limePress: '#b4e600',
  verdict: {
    zeroday: { solid: '#ff5c73', soft: 'rgba(255,92,115,.14)', label: 'Possible zero-day' },
    known:   { solid: '#f0883e', soft: 'rgba(240,136,62,.14)', label: 'Known attack' },
    review:  { solid: '#a88bfa', soft: 'rgba(168,139,250,.14)', label: 'Needs a look' },
    normal:  { solid: '#29b0c2', soft: 'rgba(41, 176, 194, .14)', label: 'Normal' },
    invalid: { solid: '#8b949e', soft: 'rgba(139,148,158,.14)', label: 'Invalid input' },
  },
  status: { ok: '#c8ff00', warn: '#e6b450', err: '#ff5c73' },
  colorway: ['#29b0c2', '#a88bfa', '#f0883e', '#ff5c73'],
};
```

### JSON (design tokens)

```json
{
  "neutral": { "bg-sunken": "#050607", "bg": "#000000", "surface": "#0C0D0F", "surface-2": "#15171A",
               "surface-3": "#1D2024", "line": "#24272C", "line-strong": "#363A41" },
  "text":    { "primary": "#E8EAED", "secondary": "#A8AEB7", "tertiary": "#868D97", "on-accent": "#0B0C0E" },
  "accent":  { "lime": "#C8FF00", "lime-hover": "#D8FF4D", "lime-press": "#B4E600" },
  "verdict": { "zeroday": "#FF5C73", "known": "#F0883E", "review": "#A88BFA", "normal": "#29B0C2", "invalid": "#8B949E" },
  "status":  { "ok": "#C8FF00", "warn": "#E6B450", "err": "#FF5C73" }
}
```

---

## 8. Rules

| ✅ Do | ❌ Don't |
|---|---|
| Use tokens only; add a token if something is missing | Hard-code hex values inside components |
| Use flat solid fills and translucent soft tones | Use gradients, glows, neon shadows or glass effects |
| Keep red-rose `#FF5C73` for zero-day (and connection errors) only | Use red for "delete", "close" or generic emphasis |
| Keep lime for interaction and single-hue charts only | Use lime as a verdict colour or a stream-chart series |
| Pair every verdict colour with its label or dash | Use colour as the only signal |
| Use `#E8EAED` as the brightest text | Use pure white `#FFF` for text (it halates on black) |
| Give every card a 1px `--line` border | Rely on fill alone to separate a card from the black page |
| Keep the chrome greyscale so the chart stands out | Add extra accent colours to the chrome |

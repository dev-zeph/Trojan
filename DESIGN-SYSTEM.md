# Trojan Design System

**One system, two apps.** This governs both `trojan-web` (the marketing site and
dashboard) and `desktop/` (the Tauri app). A user should be able to move between
them and never doubt they are the same product.

Implemented on the web in `trojan-web` commit `4c77e1b`, branch `UI/UX-revamp`.
Every colour below carries a **measured** WCAG contrast ratio, not an estimated
one. If you change a value, re-measure it — the script is at the bottom.

---

## 1. The thesis

The old design was a single flat grey (`#f2f2f3`) that never changed from the top
of a page to the bottom, in an entirely achromatic palette — every token had
chroma `0`. Two consequences:

- **Nothing had hierarchy.** With no colour, meaning could only be carried by
  grey text at varying opacity, and the greys that were faint enough to read as
  "secondary" were too faint to pass contrast.
- **It read as unstyled.** Not ugly — *unfinished*.

The fix is two moves, in this order:

1. **Rhythm.** Alternate a warm paper ground with **true-black bands**. The
   reference is floqer.com, whose off-white (`#f6f6f6`) is nearly identical to
   what Trojan already had — but roughly **56% of their page is `#000`**. The
   rhythm was the design, not the hex.
2. **One accent, used sparingly.** `#7c3aed`, lifted from the desktop app's own
   `--purple` (the one-shot scan button fill). Floqer's orange appears in exactly
   two places on their homepage: an 18×18px badge and a striped underline.

> **Do not spend the accent on decoration.** It marks the primary action, the
> active state, links, focus, and nothing else.

---

## 2. Colour

### Grounds

| Token | Value | Notes |
|---|---|---|
| `--bg` / `--color-bg` | `#f7f6f4` | Warm paper. Replaces the cold `#f2f2f3` / `oklch(0.99 0 0)`. |
| `--card` | `#ffffff` | Raised surfaces only. Not a default. |
| `--muted` / `--color-surface` | `#edeae5` | The subtle step — secondary bands, hover fills. |
| `--band` / `--color-band` | `#0c0c0e` | True-black emphasis band. |
| `--band-2` | `#151519` | Panels sitting *on* a band. |

### Ink — measured on `#f7f6f4`

| Token | Value | Ratio | Use |
|---|---|---|---|
| `--fg` / `--color-text` | `#17171a` | **16.56:1** | Body text. |
| `--muted-fg` / `--color-muted` | `#56565e` | **6.73:1** | Secondary text, captions. |
| `--input` / `--color-edge` | `#8a8a92` | **3.17:1** | Control edges, real borders. |
| `--border` / `--color-divider` | `#d3d0ca` | 1.3:1 | **Decorative hairlines only.** Never a control boundary. |

### Ink on the black band — measured on `#0c0c0e`

| Token | Value | Ratio |
|---|---|---|
| `--color-on-band` | `#f4f4f2` | **17.75:1** |
| `--color-on-band-muted` | `#a2a2ab` | **7.72:1** |
| `--color-edge-band` | `#63636d` | **3.29:1** |

### Accent — two stops, and you need both

No single purple works on both grounds. This is not a nicety; it is why the
system has two tokens.

| Token | Value | On paper | On band | Use |
|---|---|---|---|---|
| `--primary` / `--color-accent` | `#7c3aed` | **5.28:1** ✅ | 3.43:1 ❌ | Links, fills, focus on light ground. |
| `--accent-lift` | `#a78bfa` | 2.52:1 ❌ | **7.18:1** ✅ | Everything accent-coloured on a dark ground. |
| `--accent-deep` | `#6d28d9` | **6.58:1** | — | Hover / pressed on light. |
| `--accent-wash` | `#f1ebfe` | — | — | Tinted informational surface. |

- White on `#7c3aed` = **5.70:1** ✅ — a filled primary button on paper.
- White on `#a78bfa` = **2.72:1** ❌ — **on a band, the fill is `#a78bfa` and the
  label is `#0c0c0e` (7.18:1).** Do not put white on the light purple.

> **Why purple and not Floqer's orange.** `#7c3aed` clears AA *as text* on a
> light ground, so it can be a link colour. `#ff4f12` is 3.05:1 — which is
> precisely why Floqer only ever uses theirs as a fill and a stripe, never as
> body copy. Purple also already existed in the desktop app, so the two apps
> converge instead of both moving.

### Severity — two stops each, both AA on their own ground

The previous five grade colours **all failed**: `#16a34a` 2.95, `#65a30d` 2.76,
`#ca8a04` 2.63, `#ea580c` 3.18, `#dc2626` 4.32. On a security product, severity
is the first thing anyone reads.

| Level | On paper | Ratio | On band | Ratio | Wash |
|---|---|---|---|---|---|
| Critical | `#b3261e` | 6.05:1 | `#ff9b92` | 9.64:1 | `#fdeceb` |
| High | `#a44b08` | 5.42:1 | `#ffb067` | 10.85:1 | `#fdf2e6` |
| Medium | `#8a6100` | 5.13:1 | `#e8c25a` | 11.44:1 | `#faf3e1` |
| Low / pass | `#187444` | 5.37:1 | `#5fd694` | 10.73:1 | `#e9f6ee` |
| Info | `#6d28d9` | 6.58:1 | `#a78bfa` | 7.18:1 | `#f1ebfe` |

**Colour is never the only cue.** Every severity chip carries a glyph *and* the
written word:

| Level | Glyph |
|---|---|
| Critical | filled triangle |
| High | filled square |
| Medium | filled circle |
| Low | cross / plus |

This survives greyscale, print, and the roughly 1 in 12 men who cannot separate
red from green.

---

## 3. Typography

Three faces, three jobs. The web loads them via `next/font`; the desktop bundles
them via `@fontsource` (already installed — see `desktop/src/main.tsx`).

| Face | Role |
|---|---|
| **Instrument Sans** | Display + body. Sentence case, tight leading. |
| **Barlow Condensed** | **Labels only** — eyebrows, table headers, chips, spec plates. |
| **JetBrains Mono** | Data, commands, hex values, token counts, file paths. |

### The rule that matters

**Headings are sentence case.** The old design set every heading in condensed
uppercase, which shouts and reads slower. Barlow Condensed survives *only* where
a label is genuinely a label. If it is a sentence, it is not a label.

```
Know every vulnerability            ← Instrument Sans, sentence case
before it ships.

SEVERITY · SCANNERS · TOKENS        ← Barlow Condensed caps, 12px, .15em
```

### Scale

| Role | Size | Leading | Tracking |
|---|---|---|---|
| Display / h1 | `clamp(38px, 5.4vw, 64px)` | 1.04 | −0.022em |
| Section / h2 | `clamp(28px, 3.6vw, 44px)` | 1.04 | −0.02em |
| h3 | 19px | 1.25 | −0.012em |
| Body | **15px** | 1.6 | — |
| Secondary | 13–14px | 1.6 | — |
| Label (condensed caps) | **12px** | 1 | .14–.15em |
| Mono / data | 13px | 1.5 | — |

### Floor: **12px. No exceptions for functional text.**

The only permitted sub-12px text is inside a *deliberate simulation of a
document at reduced scale* (the Labs report preview). If a user is meant to read
it to operate the product, it is ≥12px.

---

## 4. Form

| Property | Value |
|---|---|
| **Border radius** | **`0`. Everywhere.** No exceptions, no pills. Floqer is 0 on every button; Trojan already was. |
| Spacing scale | 4 · 8 · 12 · 16 · 24 · 32 · 48 · 64 px |
| Container | max 1340px, padding `clamp(20px, 4vw, 56px)` |
| Minimum target | **44 × 44px** (WCAG 2.5.8 floor is 24; both platform vendors publish 44). Close the gap with **padding, not font-size**. |
| Focus ring | `2px solid var(--ring)` at `outline-offset: 2px`. Declared **unlayered** so `outline-none` utilities cannot suppress it. |

### Accent devices

Two, both already in the codebase and both previously colourless:

- **Stripe** — `repeating-linear-gradient(90deg, accent 0 5px, transparent 5px 10px)`,
  used as a thick underline on one word of a heading. This is Floqer's move.
- **Hatch** — `repeating-linear-gradient(-45deg, transparent 0 7px, accent 7px 8px)`,
  used as a short rule above a band heading. This is Trojan's own blueprint
  language; it just had no colour.

Keep the **blueprint corner registration marks**. They are the most distinctive
thing the brand owns.

---

## 5. Components

### Buttons

```
height 46px (38px for -sm) · padding 0 22px · radius 0 · weight 600 · 15px
```

| Variant | Paper ground | Black band |
|---|---|---|
| Primary | bg `#7c3aed`, text `#fff` | bg `#a78bfa`, text `#0c0c0e` |
| Ghost | transparent, 1px `#8a8a92`, text `#17171a` | transparent, 1px `#63636d`, text `#f4f4f2` |
| Dark | bg `#17171a`, text `#f7f6f4` | bg `#f4f4f2`, text `#0c0c0e` |

Primary CTAs take a trailing `→` (`<span aria-hidden="true">→</span>`).

### Chips

- **Token chip** — accent text on `--accent-wash`, 1px accent border, 12px
  condensed caps, leading 7px square. Says *what something costs*, e.g.
  `100 TOKENS`. This replaced the gold "PRO" pill, which is retired.
- **Severity chip** — glyph + word + colour, per the table in §2.

### Inputs

```
min-height 46px · 1px solid var(--input) · bg var(--card) · 15px
```

Every field needs a **programmatically associated label** — `<label for>` ↔
`<input id>`, or an `aria-label` where a visible label genuinely does not fit.
A placeholder is not a label: it disappears the moment someone types.

### Bands, and what they mean on desktop

On the **web**, a band is a full-bleed black section; the homepage runs ~33%
black across four of them.

On the **desktop app** there is no scrolling marketing narrative, so the band
translates to the app's existing dark chrome:

- The **sidebar** (`--sb-bg: #0d0d10`) is the band. It already exists.
- Terminal / xterm panes, the MCP hub, and print-report headers are bands.
- Anything on those grounds follows the **band column** of every table above —
  `--accent-lift`, not `--accent`; `--color-on-band`, not `--fg`.

> **The trap.** On the web, hundreds of inline styles read `var(--color-text)`
> directly, and an inline style beats any rule you can write. Putting them on a
> black band left ink at **1.09:1 — invisible**. The fix was to have `.band`
> *redefine the ink tokens themselves* rather than only setting `color`. Do the
> same for any dark surface in the desktop app.

---

## 6. Desktop: current state

**A substantial port already landed** (uncommitted, on branch `UI/UX-revamp`,
10 files). It is good work and builds clean. What it did:

- ✅ Tokens in `desktop/src/App.css` synced exactly to the web values above
- ✅ `--radius: 0`
- ✅ `--input` split out from `--border`
- ✅ All three fonts bundled via `@fontsource` and imported in `src/main.tsx`
  (correct for Tauri — local, not CDN)
- ✅ `:focus-visible` added. **The desktop previously had no visible keyboard
  focus indicator anywhere.**
- ✅ `--destructive` / `--success` / `--warning` consolidated from ~15 ad hoc hex values

### What remains — the component layer

The token layer is done; the components have not been brought up to it yet.

**1. Type floor — 83 declarations still below 12px.**

| Size | Count |
|---|---|
| 9px | 5 |
| 9.5px | 2 |
| 10px | 18 |
| 10.5px | 1 |
| 11px | 44 |
| 11.5px | 13 |

That is **37% of the 225 font-size declarations in `App.css`**. Raise to the
12px floor; keep hierarchy via weight, colour and the condensed label face.

**2. `.sev-badge` — `App.css:1310`.** Still `9px`, and the severity colours are
still the old failing set: `.sev-high` is `#ea580c` (3.47:1), and the washes are
hardcoded `rgba(220,38,38,…)` (i.e. `#dc2626`) rather than the new
`--destructive`. **Severity badges are the most important thing in the app and
are currently its smallest, lowest-contrast text.** Port §2, including glyphs.

**3. Grade colours — `App.css:1044–1048`.** `.lab-grade-a` through `-f` are the
exact five values replaced on the web (`#16a34a`, `#65a30d`, `#ca8a04`,
`#ea580c`, `#dc2626`). Swap for the severity ramp.

**4. `outline: none` × 5.** Each can suppress the new focus ring. Audit and
remove, or pair with a `:focus-visible` that restores it.

**5. Reduced motion.** 68 transitions and 10 `@keyframes` against only 2
`prefers-reduced-motion` blocks. Add a global guard:

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: .001ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: .001ms !important;
  }
}
```

**6. `#7c3aed` on the sidebar = 3.41:1.** Anywhere the accent lands on
`--sb-bg`, it must be `--accent-lift`. Check the ~90 rules that reference
`--purple` directly and re-point the dark-ground ones.

**7. Radius.** 106 `border-radius` declarations across 8 different values
(`4px`, `6px`, `8px`, `3px`, `5px`, `50%`, `0`, `var(--radius)`). `--radius` is
now `0`, but the hardcoded ones will not follow. Keep `50%` for avatars and
spinners; everything else goes to 0.

**8. Barlow Condensed is loaded but unused.** No label-face convention exists in
the desktop yet. Apply it to section headings, table headers, and chips — it is
what will make the two apps *look* like one product.

---

## 7. Pitfalls — all of these bit me on the web

1. **Self-referencing custom properties.** `--font-mono: var(--font-mono), …` is
   a cycle; the property becomes invalid and every use silently falls back. This
   is how JetBrains Mono was downloaded on every page load and never rendered
   for months. Alias to a *different* name (`--font-code`).
2. **Specificity ties resolve by source order.** `.landing-root .band a` and
   `.landing-root a.btn-primary` are both `(0,2,1)`; the later one won and
   painted a button's label the same colour as its own fill. Put generic rules
   before specific ones.
3. **Inline styles beat everything.** Rebind tokens on the container rather than
   fighting them (§5).
4. **Do not rebind semantic colours on a dark container blindly.** The Labs
   report preview is a *light card sitting on a black band*; flipping the grade
   colours there put band-variant colours on a light surface at 1.57:1.
5. **`transform` does nothing on an inline box.** A skip link parked with
   `translateY(-120%)` renders in the flow unless it is `inline-block`.
6. **Restart the dev server after editing global CSS.** Turbopack served a stale
   `globals.css` and cost me a debugging cycle chasing a fix that had worked.

---

## 8. Verify, don't assert

Every ratio here was measured. Re-measure anything you change:

```python
def lin(c):
    c /= 255
    return c/12.92 if c <= 0.04045 else ((c+0.055)/1.055)**2.4

def lum(rgb):
    r, g, b = [lin(x) for x in rgb]
    return 0.2126*r + 0.7152*g + 0.0722*b

def contrast(fg, bg):
    a, b = lum(fg), lum(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)

def hx(s):
    s = s.lstrip('#')
    return tuple(int(s[i:i+2], 16) for i in (0, 2, 4))

print(round(contrast(hx('#56565e'), hx('#f7f6f4')), 2))   # 6.73
```

Thresholds: **4.5:1** body text · **3:1** large text (≥24px, or ≥18.66px bold),
UI component boundaries, and focus indicators.

### Definition of done

Run this against the app and expect zero on every count:

- Contrast failures at the thresholds above
- Functional text below 12px
- Inputs without a programmatic label
- Interactive targets below 44×44 (excluding links inline in prose)
- Skipped heading levels; more than one `h1` per view
- Animation with no `prefers-reduced-motion` path

---

## 9. One-line summary for the eventual reviewer

> Warm paper `#f7f6f4` and true black `#0c0c0e`, one purple `#7c3aed` used only
> for action and focus, Instrument Sans in sentence case with Barlow Condensed
> reserved for labels, zero radius, 44px targets, 12px type floor, and severity
> that never relies on colour alone.

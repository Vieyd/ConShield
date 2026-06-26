# ConShield UI design system

This is a compact guide for Web UI polish tasks. It is not a full component library.

## Direction

- Style: Apple-like minimalism plus enterprise dashboard clarity.
- Density: medium.
- Accent: blue for primary actions and navigation.
- Green: only success/OK/security-positive states.
- Dark theme: soft graphite surfaces, never pure black.
- Technical values: Russian display text first, muted technical code second.

## Status and severity pills

Use the shared status component for statuses and severities:

```html
<span class="app-status app-status-warning">
  <span class="app-status-dot" aria-hidden="true"></span>
  <span>Предупреждение</span>
</span>
```

Rules:

- use `.app-status` with one semantic color class;
- keep the dot visible but secondary;
- avoid text shadows, text stroke, neon colors, and raw Bootstrap badge colors;
- long labels may wrap inside the pill and must not be cropped;
- raw enum/status values should be muted secondary text when they are useful.

## Cards and metrics

Use `.app-card` for framed surfaces and `.app-metric-card` for dashboard counters. Metric cards need enough internal padding, a muted label, a clear value, and room for badges without touching the card edge.

## Tables

Wrap data tables in:

```html
<div class="app-table-card">
  <div class="app-table-scroll">
    <table class="table table-striped align-middle app-table">
    </table>
  </div>
</div>
```

Table headers are sticky, rows have calm hover color, and wide tables scroll horizontally inside the card.

## Actions

Row and toolbar actions should use `.app-action-group` so buttons share height, spacing, and alignment. Prefer blue primary actions, neutral secondary actions, readable amber warning actions, and readable red danger actions.

## Theme toggle

Authenticated layout exposes a right-side theme toggle. It stores only `light` or `dark` in `localStorage`; it must never use cookies, tokens, passwords, or server-side state.

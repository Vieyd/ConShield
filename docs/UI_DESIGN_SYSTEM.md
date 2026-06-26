# ConShield UI design system

This is a compact guide for Web UI polish tasks. It is not a full component library.

## Direction

- Style: Apple-like minimalism plus enterprise dashboard clarity.
- Density: medium.
- Accent: blue for primary actions and navigation.
- Green: only success/OK/security-positive states.
- Dark theme: soft graphite surfaces, never pure black.
- Technical values: Russian display text first, muted technical code second.
- Responsive targets: usable at 1366×768, comfortable at 1536×864, spacious at 1920×1080+.
- Main list pages are compact summaries. Raw JSON and long technical fields belong in details pages, detail actions, or muted/truncated secondary text.
- Theme must be applied before CSS paint from the safe `conshield.theme` light/dark preference to avoid dark-to-light navigation flash.

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
- raw enum/status values should be muted secondary text when they are useful;
- `Высокий` uses readable orange, distinct from slate/blue-gray `Информационный`.

## Cards and metrics

Use `.app-card` for framed surfaces and `.app-metric-card` for dashboard counters. Metric cards need enough internal padding, a muted label, a clear value, and room for badges without touching the card edge.

## Tables

Wrap data tables in:

```html
<div class="app-table-card">
  <div class="app-table-scroll-wrap" data-table-scroll-sync>
    <div class="app-table-scrollbar-top" aria-hidden="true">
      <div class="app-table-scrollbar-inner"></div>
    </div>
    <div class="app-table-scroll">
      <table class="table table-striped align-middle app-table">
      </table>
    </div>
  </div>
</div>
```

Table headers are sticky, rows have calm hover color, and wide tables scroll horizontally inside the card. The mirrored top scrollbar is a visual affordance for long pages; if JavaScript is unavailable, the real bottom scroll container remains usable. Use a sticky `.app-table-actions-col` for right-side action columns when wide tables would otherwise hide controls. Numeric IDs use nowrap classes, while long GUIDs/source systems use truncated muted technical-code classes with the full value in `title`.

Wide tables must keep the horizontal scrollbar discoverable in both themes. Use the shared `.app-table-scroll-wrap` / `.app-table-scrollbar-top` pattern instead of adding visible text hints or per-page banners.

Heavy list pages must use server-side pagination or an explicit server-side cap. Apply filters before `Count`, `Skip`, and `Take`; use a stable descending date/id sort; and preserve filters in pagination links.

## Actions

Row and toolbar actions should use `.app-action-group` so buttons share height, spacing, and alignment. Prefer blue primary actions, neutral secondary actions, readable amber warning actions, and readable red danger actions.

## Theme toggle

Authenticated layout exposes a right-side theme toggle, and the login page exposes the same control before authentication. It stores only `light` or `dark` in `localStorage` plus the safe non-sensitive `conshield.theme` cookie used to avoid first-paint theme flash; it must never store tokens, passwords, user identifiers, or other secrets.

## Login controls

The login page must keep authentication semantics unchanged while providing basic UX controls: the shared theme toggle and a `type="button"` password visibility toggle that switches only the input type and updates accessible labels. Password values must never be logged, stored, or sent anywhere except the normal login form submit.

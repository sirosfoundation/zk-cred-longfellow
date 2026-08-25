# Decks

## siros-trust-infrastructure.pptx

A 10-slide overview of the SIROS trust list stack:

| Repo / site | Role |
|---|---|
| [g119612](https://github.com/sirosfoundation/g119612) | Go library for ETSI TS 119 612 (TSL) and TS 119 602 (LoTE), plus the `tsl-tool` CLI |
| [trust-lists](https://github.com/sirosfoundation/trust-lists) | Trust list source data as YAML + certificates, governed by pull request |
| [trust.siros.org](https://trust.siros.org) | The signed, published output — LoTE JSON/JWS and TSL XML on GitHub Pages |

### Styling

The deck follows the siros.org design system rather than a generic template:

- **Colour** — the `src/index.css` tokens: `--foreground` `#121721`, `--card` `#F6F7F9`,
  `--border` `#DCE1E5`, `--primary` `#295CA3`, `--muted-foreground` `#5C6270`, on white.
- **Type** — the `"Helvetica Neue", Arial, system-ui` stack from `tailwind.config.ts`;
  Arial is what actually ships, so that is what the deck names.
- **Cards** — `rounded-lg border border-border bg-card`, with the `bg-primary/10` icon
  chip from `SolutionCard.tsx`.
- **Icons** — [Lucide](https://lucide.dev), the pack named in the branding repo,
  rasterised at build time.
- **Title slide** — the site's hero image, faded into the page the way `HeroSection.tsx`
  does it.

### Rebuilding

```bash
npm install pptxgenjs react-icons react react-dom sharp
node siros-trust-infrastructure.build.js   # reads siros-logo.png and hero-bg.jpg alongside it
```

# Decks

## siros-trust-infrastructure.pptx

A 10-slide overview of the SIROS trust list stack:

| Repo / site | Role |
|---|---|
| [g119612](https://github.com/sirosfoundation/g119612) | Go library for ETSI TS 119 612 (TSL) and TS 119 602 (LoTE), plus the `tsl-tool` CLI |
| [trust-lists](https://github.com/sirosfoundation/trust-lists) | Trust list source data as YAML + certificates, governed by pull request |
| [trust.siros.org](https://trust.siros.org) | The signed, published output — LoTE JSON/JWS and TSL XML on GitHub Pages |

`siros-trust-infrastructure.build.js` regenerates the deck:

```bash
npm install pptxgenjs
node siros-trust-infrastructure.build.js   # reads siros-logo.png from the same directory
```

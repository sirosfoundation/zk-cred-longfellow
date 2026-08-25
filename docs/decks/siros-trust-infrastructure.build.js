const pptxgen = require("pptxgenjs");
const fs = require("fs");

const NAVY = "1C4587";
const NAVY_DK = "13315F";
const SLATE = "55617A";
const MIST = "EDF2F9";
const MIST_DK = "DCE5F2";
const AMBER = "C2760A";
const INK = "1A1A1A";
const W = 13.333, H = 7.5;
const M = 0.7;                       // left margin
const LOGO = "siros-logo.png";
const SANS = "Calibri";
const SERIF = "Cambria";

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.author = "SIROS Foundation";
pres.company = "SIROS Foundation";
pres.title = "SIROS Trust Infrastructure";

function newSlide() {
  const s = pres.addSlide();
  s.background = { color: "FFFFFF" };
  s.addImage({ path: LOGO, x: W - 0.7 - 1.85, y: 0.34, w: 1.85, h: 0.617 });
  return s;
}

function heading(s, kicker, title) {
  s.addText(kicker, {
    x: M, y: 0.42, w: 7.6, h: 0.28, fontFace: SANS, fontSize: 11.5, bold: true,
    color: AMBER, charSpacing: 2, margin: 0,
  });
  s.addText(title, {
    x: M, y: 0.74, w: 9.2, h: 0.62, fontFace: SERIF, fontSize: 31, bold: true,
    color: NAVY, margin: 0, valign: "top",
  });
}

// Navy circle badge with white glyph — the repeating motif
function badge(s, x, y, d, label, opts = {}) {
  s.addShape(pres.ShapeType.ellipse, {
    x, y, w: d, h: d,
    fill: { color: opts.fill || NAVY },
    line: { color: opts.fill || NAVY, width: 0 },
  });
  s.addText(label, {
    x, y, w: d, h: d, align: "center", valign: "middle", margin: 0,
    fontFace: SANS, fontSize: opts.size || 15, bold: true, color: opts.color || "FFFFFF",
  });
}

function card(s, x, y, w, h, fill) {
  s.addShape(pres.ShapeType.roundRect, {
    x, y, w, h, rectRadius: 0.09,
    fill: { color: fill || MIST },
    line: { color: fill || MIST, width: 0 },
  });
}

function footer(s, n, text) {
  s.addText(text, {
    x: M, y: H - 0.62, w: 9.6, h: 0.3, fontFace: SANS, fontSize: 9.5,
    color: "8A93A6", margin: 0, valign: "middle",
  });
  s.addText(String(n), {
    x: W - 1.3, y: H - 0.62, w: 0.6, h: 0.3, align: "right", margin: 0,
    fontFace: SANS, fontSize: 9.5, color: "8A93A6", valign: "middle",
  });
}

/* ───────────────────────── 1. Title ───────────────────────── */
{
  const s = newSlide();
  s.addShape(pres.ShapeType.ellipse, {
    x: 9.55, y: 2.05, w: 3.5, h: 3.5, fill: { color: MIST }, line: { color: MIST, width: 0 },
  });
  s.addShape(pres.ShapeType.ellipse, {
    x: 10.5, y: 3.0, w: 1.6, h: 1.6, fill: { color: NAVY }, line: { color: NAVY, width: 0 },
  });
  s.addText("Open Trust Infrastructure", {
    x: M, y: 1.72, w: 8.4, h: 0.32, fontFace: SANS, fontSize: 13, bold: true,
    color: AMBER, charSpacing: 2.4, margin: 0,
  });
  s.addText("Trust Lists for the\nEUDI Wallet Ecosystem", {
    x: M, y: 2.14, w: 8.5, h: 1.6, fontFace: SERIF, fontSize: 44, bold: true,
    color: NAVY, lineSpacing: 46, margin: 0,
  });
  s.addText(
    "Standards-based, PR-governed and HSM-signed trust anchors — from source data " +
    "in Git to signed ETSI documents on the public web.",
    { x: M, y: 3.92, w: 8.1, h: 0.7, fontFace: SANS, fontSize: 15, color: SLATE, margin: 0 }
  );

  const chips = [
    ["g119612", "Library + tsl-tool"],
    ["trust-lists", "Source data + CI"],
    ["trust.siros.org", "Published lists"],
  ];
  chips.forEach(([t, sub], i) => {
    const x = M + i * 2.72;
    card(s, x, 4.94, 2.5, 0.9, MIST);
    s.addText(t, {
      x: x + 0.22, y: 5.06, w: 2.1, h: 0.3, fontFace: SANS, fontSize: 14, bold: true,
      color: NAVY, margin: 0,
    });
    s.addText(sub, {
      x: x + 0.22, y: 5.36, w: 2.15, h: 0.28, fontFace: SANS, fontSize: 10.5,
      color: SLATE, margin: 0,
    });
  });

  s.addText("SIROS Foundation  ·  ETSI TS 119 612  ·  ETSI TS 119 602  ·  BSD-2-Clause", {
    x: M, y: H - 0.72, w: 9.6, h: 0.3, fontFace: SANS, fontSize: 10,
    color: "8A93A6", margin: 0,
  });
  s.addNotes(
    "Three artefacts, one story: g119612 is the engine, trust-lists is the governed source " +
    "of truth, trust.siros.org is the published, signed output that wallets and verifiers consume."
  );
}

/* ───────────────── 2. Why trust lists ───────────────── */
{
  const s = newSlide();
  heading(s, "THE PROBLEM", "Who is authorised to do what?");
  s.addText(
    "An issuer, a wallet and a verifier each have to answer the same question about the other side: " +
    "is this counterpart recognised by the scheme? A trust list is the signed, publicly fetchable answer.",
    { x: M, y: 1.5, w: 11.9, h: 0.5, fontFace: SANS, fontSize: 13.5, color: SLATE, margin: 0 }
  );

  // Actor flow
  const actors = [["Issuer", "signs credentials"], ["Wallet Unit", "holds & presents"], ["Verifier", "requests & checks"]];
  actors.forEach(([t, sub], i) => {
    const x = M + i * 4.06;
    card(s, x, 2.2, 3.82, 1.0, MIST);
    s.addText(t, {
      x: x + 0.3, y: 2.34, w: 3.2, h: 0.3, fontFace: SANS, fontSize: 14.5, bold: true,
      color: NAVY, margin: 0,
    });
    s.addText(sub, {
      x: x + 0.3, y: 2.66, w: 3.25, h: 0.28, fontFace: SANS, fontSize: 10.5, color: SLATE, margin: 0,
    });
    if (i < 2) {
      s.addText("→", {
        x: x + 3.84, y: 2.2, w: 0.24, h: 1.0, align: "center", valign: "middle",
        fontFace: SANS, fontSize: 18, bold: true, color: NAVY, margin: 0,
      });
    }
    s.addShape(pres.ShapeType.line, {
      x: x + 1.91, y: 3.2, w: 0, h: 0.5, line: { color: "B9C4D6", width: 1.25, dashType: "dash" },
    });
  });

  card(s, M, 3.7, 11.94, 0.72, NAVY);
  s.addText("Trust list  —  the shared anchor of authority", {
    x: M + 0.3, y: 3.7, w: 11.3, h: 0.72, valign: "middle", margin: 0,
    fontFace: SANS, fontSize: 15, bold: true, color: "FFFFFF",
  });

  // Two standards
  const stds = [
    ["ETSI TS 119 612", "Trust Status List (TSL)", "XML  ·  XML-DSIG / XAdES  ·  the format the EU LOTL and national lists already use"],
    ["ETSI TS 119 602", "List of Trusted Entities (LoTE)", "JSON  ·  JWS  ·  the newer, wallet-friendly format, with LoTL for lists of lists"],
  ];
  stds.forEach(([spec, name, body], i) => {
    const x = M + i * 6.0;
    card(s, x, 4.72, 5.6, 1.5, i === 0 ? MIST : MIST_DK);
    s.addText(spec, {
      x: x + 0.28, y: 4.88, w: 5.0, h: 0.26, fontFace: SANS, fontSize: 10.5, bold: true,
      color: AMBER, charSpacing: 1.2, margin: 0,
    });
    s.addText(name, {
      x: x + 0.28, y: 5.16, w: 5.0, h: 0.3, fontFace: SANS, fontSize: 15, bold: true,
      color: NAVY, margin: 0,
    });
    s.addText(body, {
      x: x + 0.28, y: 5.5, w: 5.05, h: 0.6, fontFace: SANS, fontSize: 11, color: SLATE, margin: 0,
    });
  });

  footer(s, 2, "Both formats are first-class here — and one converts to the other.");
  s.addNotes("The EUDI ecosystem is mid-migration: XML TSLs exist today, JSON LoTEs are where it is heading. Supporting both, and converting between them, is the point.");
}

/* ───────────────── 3. Three components ───────────────── */
{
  const s = newSlide();
  heading(s, "THE STACK", "Three repositories, one pipeline");

  const items = [
    ["1", "g119612", "The engine",
      ["Go library for TS 119 612 + TS 119 602", "tsl-tool CLI, driven by YAML pipelines", "Ships as a GitHub Action"]],
    ["2", "trust-lists", "The source of truth",
      ["Entities and providers as YAML + certs", "Every change is a reviewed pull request", "Git history is the audit log"]],
    ["3", "trust.siros.org", "The published output",
      ["Signed LoTE JSON + JWS, TSL XML", "Deployed to GitHub Pages on merge", "Fetched by wallets, verifiers, PDPs"]],
  ];

  items.forEach(([n, title, sub, lines], i) => {
    const x = M + i * 4.06;
    card(s, x, 1.66, 3.82, 3.5, MIST);
    badge(s, x + 0.3, 1.94, 0.52, n, { size: 16 });
    s.addText(title, {
      x: x + 0.3, y: 2.66, w: 3.3, h: 0.34, fontFace: SANS, fontSize: 18, bold: true,
      color: NAVY, margin: 0,
    });
    s.addText(sub, {
      x: x + 0.3, y: 3.0, w: 3.3, h: 0.28, fontFace: SANS, fontSize: 11.5, bold: true,
      color: AMBER, margin: 0,
    });
    s.addText(
      lines.map((t, j) => ({ text: t, options: { bullet: { indent: 12 }, breakLine: j < lines.length - 1 } })),
      { x: x + 0.3, y: 3.4, w: 3.25, h: 1.55, fontFace: SANS, fontSize: 11.5, color: SLATE, margin: 0, paraSpaceAfter: 7, valign: "top" }
    );
  });

  card(s, M, 5.34, 11.94, 0.86, MIST_DK);
  s.addText([
    { text: "Downstream:  ", options: { bold: true, color: NAVY } },
    { text: "go-trust consumes the published lists as an AuthZEN Trust Decision Point — parallel evaluation across ETSI TSL, LoTE, OpenID Federation and DID Web.", options: { color: SLATE } },
  ], { x: M + 0.3, y: 5.34, w: 11.3, h: 0.86, valign: "middle", fontFace: SANS, fontSize: 12, margin: 0 });

  footer(s, 3, "github.com/sirosfoundation");
  s.addNotes("Clean separation: code, data, output. Each has its own release and review cadence.");
}

/* ───────────────── 4. g119612 library ───────────────── */
{
  const s = newSlide();
  heading(s, "G119612", "One library, both ETSI formats");

  const cols = [
    ["TS 119 612  ·  TSL (XML)", [
      "Full parsing and structural validation",
      "XML digital signature validation",
      "Build an x509.CertPool straight from a TSL",
      "Brainpool curves via go-cryptoutil",
      "XSLT transform to browsable HTML",
    ]],
    ["TS 119 602  ·  LoTE (JSON)", [
      "Parse, generate, validate and publish LoTEs",
      "TSL → LoTE conversion",
      "JWS signing — file keys or PKCS#11 / HSM",
      "X.509, JWK and DID identities",
      "Merge and sequence-number management",
    ]],
  ];
  cols.forEach(([title, lines], i) => {
    const x = M + i * 6.0;
    card(s, x, 1.62, 5.6, 2.5, i === 0 ? MIST : MIST_DK);
    s.addText(title, {
      x: x + 0.3, y: 1.8, w: 5.0, h: 0.3, fontFace: SANS, fontSize: 14, bold: true,
      color: NAVY, margin: 0,
    });
    s.addText(
      lines.map((t, j) => ({ text: t, options: { bullet: { indent: 12 }, breakLine: j < lines.length - 1 } })),
      { x: x + 0.3, y: 2.18, w: 5.0, h: 1.85, fontFace: SANS, fontSize: 11.5, color: SLATE, margin: 0, paraSpaceAfter: 5, valign: "top" }
    );
  });

  s.addText([
    { text: "Packages   ", options: { bold: true, color: NAVY, fontSize: 12 } },
    { text: "etsi119612 · etsi119602 · dsig · jws · pipeline · xslt · validation · resilience · logging", options: { color: SLATE, fontSize: 12 } },
  ], { x: M, y: 4.34, w: 11.9, h: 0.3, fontFace: SANS, margin: 0 });

  const stats = [
    ["13.1k", "lines of library code"],
    ["15.0k", "lines of tests"],
    ["Go 1.26", "fully reentrant, no caching"],
    ["BSD-2", "OpenSSF Scorecard tracked"],
  ];
  stats.forEach(([big, label], i) => {
    const x = M + i * 3.02;
    card(s, x, 4.82, 2.8, 1.28, MIST);
    s.addText(big, {
      x: x + 0.24, y: 4.94, w: 2.4, h: 0.56, fontFace: SERIF, fontSize: 28, bold: true,
      color: NAVY, margin: 0,
    });
    s.addText(label, {
      x: x + 0.24, y: 5.52, w: 2.45, h: 0.46, fontFace: SANS, fontSize: 10.5, color: SLATE, margin: 0,
    });
  });

  footer(s, 4, "pkg.go.dev/github.com/sirosfoundation/g119612");
  s.addNotes("Deliberately unopinionated about caching and availability — fetch from a CDN, the library stays reentrant.");
}

/* ───────────────── 5. tsl-tool pipelines ───────────────── */
{
  const s = newSlide();
  heading(s, "G119612  ·  TSL-TOOL", "Pipelines, not bespoke scripts");

  // left: yaml sample
  card(s, M, 1.6, 5.6, 3.3, "F5F7FA");
  s.addText("pipeline.yaml", {
    x: M + 0.3, y: 1.74, w: 4.0, h: 0.28, fontFace: SANS, fontSize: 10.5, bold: true,
    color: AMBER, charSpacing: 1.2, margin: 0,
  });
  s.addText(
    "- set-fetch-options:\n" +
    "    - timeout:60s\n" +
    "- load:\n" +
    "    - https://ec.europa.eu/tools/lotl/eu-lotl.xml\n" +
    "- select:\n" +
    "    - reference-depth:2\n" +
    "- convert-to-lote:\n" +
    "- merge-lote:\n" +
    "- increment-lote-sequence:\n" +
    "- publish-lote:\n" +
    "    - ${OUTPUT_DIR}\n" +
    "    - ${PKCS11_URI}",
    { x: M + 0.3, y: 2.06, w: 5.05, h: 2.7, fontFace: "Courier New", fontSize: 10.5, color: INK, margin: 0, lineSpacing: 14 }
  );

  // right: steps
  const groups = [
    ["TSL steps", "load · select · transform · publish · generate · generate_index · report · set-fetch-options · log"],
    ["LoTE steps", "load-lote · generate-lote · generate-lotl · convert-to-lote · merge-lote · increment-lote-sequence · publish-lote"],
  ];
  groups.forEach(([t, body], i) => {
    const y = 1.6 + i * 1.96;
    card(s, 6.72, y, 5.92, 1.34, i === 0 ? MIST : MIST_DK);
    s.addText(t, {
      x: 7.0, y: y + 0.16, w: 5.2, h: 0.3, fontFace: SANS, fontSize: 14, bold: true, color: NAVY, margin: 0,
    });
    s.addText(body, {
      x: 7.0, y: y + 0.52, w: 5.35, h: 0.85, fontFace: SANS, fontSize: 11.5, color: SLATE, margin: 0,
    });
  });

  card(s, M, 5.12, 11.94, 1.06, MIST);
  s.addText([
    { text: "Reusable in CI.  ", options: { bold: true, color: NAVY } },
    { text: "tsl-tool ships as a composite GitHub Action — ", options: { color: SLATE } },
    { text: "uses: sirosfoundation/g119612@v0.7.0", options: { color: INK, fontFace: "Courier New" } },
    { text: " — downloading a pre-built binary for the runner. The same pipeline file runs locally and in the trust-lists workflows.", options: { color: SLATE } },
  ], { x: M + 0.3, y: 5.12, w: 11.3, h: 1.06, valign: "middle", fontFace: SANS, fontSize: 11.5, margin: 0 });

  footer(s, 5, "One YAML file per trust list decides what that list is and how it is signed.");
  s.addNotes("The pipeline abstraction is what lets trust-lists stay pure data: each directory carries its own .pipeline.yaml.");
}

/* ───────────────── 6. trust-lists as data ───────────────── */
{
  const s = newSlide();
  heading(s, "TRUST-LISTS", "Trust data as code");

  card(s, M, 1.6, 5.6, 3.6, "F5F7FA");
  s.addText("lists/<instance>/", {
    x: M + 0.3, y: 1.74, w: 4.0, h: 0.28, fontFace: SANS, fontSize: 10.5, bold: true,
    color: AMBER, charSpacing: 1.2, margin: 0,
  });
  s.addText(
    ".pipeline.yaml      what this list is\n" +
    "scheme.yaml         operator, type, territory\n" +
    "lotl.yaml           pointers (lists of lists)\n" +
    "entities/           LoTE trusted entities\n" +
    "  <entity>/\n" +
    "    entity.yaml     names, entityId, services\n" +
    "    cert.pem        X.509\n" +
    "    key.jwk         JWK\n" +
    "providers/          TSL service providers\n" +
    "  <provider>/\n" +
    "    provider.yaml\n" +
    "    <service>/cert.pem + cert.yaml",
    { x: M + 0.3, y: 2.08, w: 5.1, h: 3.0, fontFace: "Courier New", fontSize: 10, color: INK, margin: 0, lineSpacing: 13.5 }
  );

  const steps = [
    ["Propose", "A contributor opens a PR adding or amending an entity directory."],
    ["Validate", "CI runs every pipeline in validation mode — structure and certificates must parse."],
    ["Review", "A human approves the change to the trust anchor set. Nothing merges unreviewed."],
    ["Publish", "Merge to main rebuilds, signs and deploys the affected lists."],
  ];
  steps.forEach(([t, body], i) => {
    const y = 1.6 + i * 0.92;
    badge(s, 6.72, y + 0.1, 0.46, String(i + 1), { size: 14 });
    s.addText(t, {
      x: 7.34, y: y + 0.06, w: 5.3, h: 0.28, fontFace: SANS, fontSize: 14, bold: true, color: NAVY, margin: 0,
    });
    s.addText(body, {
      x: 7.34, y: y + 0.36, w: 5.3, h: 0.48, fontFace: SANS, fontSize: 11.5, color: SLATE, margin: 0,
    });
  });

  card(s, M, 5.42, 11.94, 0.76, MIST);
  s.addText([
    { text: "The result:  ", options: { bold: true, color: NAVY } },
    { text: "every trusted entity, every certificate and every removal is attributable, reviewable and reversible in Git history.", options: { color: SLATE } },
  ], { x: M + 0.3, y: 5.42, w: 11.3, h: 0.76, valign: "middle", fontFace: SANS, fontSize: 12, margin: 0 });

  footer(s, 6, "github.com/sirosfoundation/trust-lists");
  s.addNotes("The governance claim is the real product here — the file format is incidental, the review trail is not.");
}

/* ───────────────── 7. Signing & key custody ───────────────── */
{
  const s = newSlide();
  heading(s, "TRUST-LISTS  ·  SIGNING", "Keys never leave the token");

  s.addText(
    "All signing goes through one PKCS#11 interface, so the same pipeline runs against an ephemeral CI key or a hardware " +
    "security module. Only the mode changes.",
    { x: M, y: 1.5, w: 11.9, h: 0.5, fontFace: SANS, fontSize: 13.5, color: SLATE, margin: 0 }
  );

  const modes = [
    ["dev", "Ephemeral SoftHSM", "New key every build", "GitHub-hosted runner", "CI testing, quick validation", MIST],
    ["softhsm", "Persistent SoftHSM2", "Token pinned to the host", "Self-hosted runner", "Staging, pre-production", MIST],
    ["yubihsm", "YubiHSM 2", "Hardware-held key", "Self-hosted runner", "Production", MIST_DK],
  ];
  modes.forEach(([mode, kind, persist, runner, use, fill], i) => {
    const x = M + i * 4.06;
    card(s, x, 2.2, 3.82, 2.86, fill);
    s.addText(mode, {
      x: x + 0.3, y: 2.38, w: 3.2, h: 0.36, fontFace: "Courier New", fontSize: 17, bold: true,
      color: i === 2 ? AMBER : NAVY, margin: 0,
    });
    s.addText(kind, {
      x: x + 0.3, y: 2.76, w: 3.25, h: 0.3, fontFace: SANS, fontSize: 13, bold: true, color: NAVY, margin: 0,
    });
    [["Key", persist], ["Runner", runner], ["Use", use]].forEach(([k, v], j) => {
      s.addText([
        { text: k + "   ", options: { bold: true, color: NAVY } },
        { text: v, options: { color: SLATE } },
      ], { x: x + 0.3, y: 3.2 + j * 0.56, w: 3.25, h: 0.46, fontFace: SANS, fontSize: 10.5, margin: 0 });
    });
  });

  const notes = [
    ["LoTE → JWS", "JSON lists are signed as JSON Web Signatures alongside the unsigned document."],
    ["TSL → XML-DSIG", "XML lists carry an enveloped XAdES signature."],
    ["Verified in CI", "The workflow proves signing certificate and key match before it publishes anything."],
  ];
  notes.forEach(([t, body], i) => {
    const x = M + i * 4.06;
    s.addText([
      { text: t + "\n", options: { bold: true, color: NAVY, fontSize: 12 } },
      { text: body, options: { color: SLATE, fontSize: 10.5 } },
    ], { x, y: 5.34, w: 3.82, h: 1.0, fontFace: SANS, margin: 0 });
  });

  footer(s, 7, "A scheduled workflow reissues the signing certificate before it expires.");
  s.addNotes("Signing mode is a repository variable, so promoting from dev to hardware is a configuration change, not a code change.");
}

/* ───────────────── 8. What is published ───────────────── */
{
  const s = newSlide();
  heading(s, "TRUST.SIROS.ORG", "What is live today");

  const rows = [
    ["siros-demo", "LoTE", "Demo scheme — SIROS Identity Credential Issuer"],
    ["siros-demo-lotl", "LoTL", "List of trusted lists, pointing at the demo LoTE"],
    ["multipaz.org", "LoTE", "Verifier entity for the multipaz.org ecosystem"],
    ["digital-credentials.dev", "LoTE", "Verifier entity for digital-credentials.dev"],
    ["siros-multipaz-verifier", "LoTE", "SIROS-hosted multipaz-ppid verifier"],
    ["ewc-demo", "TSL → LoTE", "EWC Consortium demo — 17 trust service providers"],
  ];

  const y0 = 1.66, rh = 0.5;
  s.addText("TRUST LIST", { x: M + 0.3, y: y0, w: 3.2, h: 0.34, fontFace: SANS, fontSize: 9.5, bold: true, color: SLATE, charSpacing: 1.2, margin: 0, valign: "middle" });
  s.addText("TYPE", { x: M + 3.6, y: y0, w: 1.5, h: 0.34, fontFace: SANS, fontSize: 9.5, bold: true, color: SLATE, charSpacing: 1.2, margin: 0, valign: "middle" });
  s.addText("CONTENT", { x: M + 5.2, y: y0, w: 4.6, h: 0.34, fontFace: SANS, fontSize: 9.5, bold: true, color: SLATE, charSpacing: 1.2, margin: 0, valign: "middle" });

  rows.forEach(([name, type, desc], i) => {
    const y = y0 + 0.4 + i * rh;
    if (i % 2 === 0) card(s, M, y, 9.7, rh - 0.06, "F5F7FA");
    s.addText(name, { x: M + 0.3, y, w: 3.3, h: rh - 0.06, valign: "middle", margin: 0, fontFace: "Courier New", fontSize: 11.5, bold: true, color: NAVY });
    s.addText(type, { x: M + 3.6, y, w: 1.6, h: rh - 0.06, valign: "middle", margin: 0, fontFace: SANS, fontSize: 11, bold: true, color: AMBER });
    s.addText(desc, { x: M + 5.2, y, w: 4.7, h: rh - 0.06, valign: "middle", margin: 0, fontFace: SANS, fontSize: 11, color: SLATE });
  });

  card(s, 10.66, 1.66, 1.98, 3.4, MIST);
  s.addText("Per list", { x: 10.9, y: 1.82, w: 1.6, h: 0.28, fontFace: SANS, fontSize: 10.5, bold: true, color: AMBER, margin: 0 });
  s.addText(
    [".json  unsigned", ".json.jws  signed", ".xml  XML form"]
      .map((t, j) => ({ text: t, options: { bullet: { indent: 12 }, breakLine: j < 2 } })),
    { x: 10.9, y: 2.16, w: 1.62, h: 1.5, fontFace: SANS, fontSize: 10.5, color: SLATE, margin: 0, paraSpaceAfter: 8 }
  );
  s.addText("Plus a generated index.html landing page listing every artefact.", {
    x: 10.9, y: 3.9, w: 1.62, h: 1.0, fontFace: SANS, fontSize: 10.5, color: SLATE, margin: 0,
  });

  card(s, M, 5.26, 11.94, 0.9, MIST_DK);
  s.addText([
    { text: "Distribution points are stable URLs — ", options: { color: SLATE } },
    { text: "https://trust.siros.org/<instance>.json", options: { fontFace: "Courier New", color: INK } },
    { text: "  — served from GitHub Pages and referenced from the scheme metadata itself.", options: { color: SLATE } },
  ], { x: M + 0.3, y: 5.26, w: 11.3, h: 0.9, valign: "middle", fontFace: SANS, fontSize: 11.5, margin: 0 });

  footer(s, 8, "trust.siros.org");
  s.addNotes("The mix is deliberate: demo schemes to exercise the tooling, plus real interop targets like EWC and multipaz.");
}

/* ───────────────── 9. End-to-end flow ───────────────── */
{
  const s = newSlide();
  heading(s, "END TO END", "From pull request to trust anchor");

  const flow = [
    ["Pull request", "An entity is added, amended or withdrawn under lists/."],
    ["Validation", "CI runs each pipeline with tsl-tool; malformed data never merges."],
    ["Review & merge", "A maintainer approves; main becomes the new state of the world."],
    ["Build & sign", "Pipelines regenerate every list and sign via PKCS#11 — JWS or XAdES."],
    ["Publish", "Artefacts and a fresh index deploy to GitHub Pages at trust.siros.org."],
    ["Consume", "Wallets, verifiers and go-trust fetch the list and build a certificate pool."],
  ];

  flow.forEach(([t, body], i) => {
    const col = i % 3, row = Math.floor(i / 3);
    const x = M + col * 4.06, y = 1.68 + row * 2.05;
    card(s, x, y, 3.82, 1.8, row === 0 ? MIST : MIST_DK);
    badge(s, x + 0.3, y + 0.26, 0.46, String(i + 1), { size: 14 });
    s.addText(t, {
      x: x + 0.9, y: y + 0.28, w: 2.75, h: 0.42, valign: "middle", margin: 0,
      fontFace: SANS, fontSize: 14.5, bold: true, color: NAVY,
    });
    s.addText(body, {
      x: x + 0.3, y: y + 0.86, w: 3.25, h: 0.8, fontFace: SANS, fontSize: 11.5, color: SLATE, margin: 0,
    });
  });

  s.addText("→", { x: M + 3.84, y: 1.68, w: 0.24, h: 1.8, align: "center", valign: "middle", margin: 0, fontFace: SANS, fontSize: 16, bold: true, color: NAVY });
  s.addText("→", { x: M + 7.9, y: 1.68, w: 0.24, h: 1.8, align: "center", valign: "middle", margin: 0, fontFace: SANS, fontSize: 16, bold: true, color: NAVY });
  s.addText("→", { x: M + 3.84, y: 3.73, w: 0.24, h: 1.8, align: "center", valign: "middle", margin: 0, fontFace: SANS, fontSize: 16, bold: true, color: NAVY });
  s.addText("→", { x: M + 7.9, y: 3.73, w: 0.24, h: 1.8, align: "center", valign: "middle", margin: 0, fontFace: SANS, fontSize: 16, bold: true, color: NAVY });

  s.addText("No step in this chain is manual, and no step is unrecorded.", {
    x: M, y: 5.72, w: 9.6, h: 0.34, fontFace: SANS, fontSize: 13, italic: true, color: NAVY, margin: 0,
  });

  footer(s, 9, "Minutes from merge to a signed list on the public web.");
  s.addNotes("Worth stressing that steps 4 and 5 are the same code contributors run locally — no bespoke publishing machinery.");
}

/* ───────────────── 10. Why it matters ───────────────── */
{
  const s = newSlide();
  heading(s, "IN SUMMARY", "Why build it this way");

  const points = [
    ["Standards first", "Nothing proprietary in the wire formats: ETSI TS 119 612 and TS 119 602, verifiable by any conforming implementation."],
    ["Auditable by construction", "Trust anchors live in reviewed YAML, not in a database somebody can edit quietly."],
    ["Hardware-backed", "One PKCS#11 path from laptop to YubiHSM; the production key never leaves the token."],
    ["Reusable", "g119612 is an independent BSD-2 library — the pipeline works for anyone's trust list, not just ours."],
  ];
  points.forEach(([t, body], i) => {
    const col = i % 2, row = Math.floor(i / 2);
    const x = M + col * 6.0, y = 1.66 + row * 1.62;
    badge(s, x, y + 0.04, 0.44, "◆", { size: 13 });
    s.addText(t, {
      x: x + 0.62, y: y, w: 4.9, h: 0.34, valign: "middle", margin: 0,
      fontFace: SANS, fontSize: 16, bold: true, color: NAVY,
    });
    s.addText(body, {
      x: x + 0.62, y: y + 0.4, w: 4.95, h: 0.9, fontFace: SANS, fontSize: 11.5, color: SLATE, margin: 0,
    });
  });

  card(s, M, 5.0, 11.94, 1.2, NAVY);
  s.addText("Explore", {
    x: M + 0.36, y: 5.16, w: 2.0, h: 0.28, fontFace: SANS, fontSize: 10.5, bold: true,
    color: "9FBBE6", charSpacing: 1.4, margin: 0,
  });
  s.addText(
    "trust.siros.org   ·   github.com/sirosfoundation/trust-lists   ·   github.com/sirosfoundation/g119612",
    { x: M + 0.36, y: 5.48, w: 11.2, h: 0.4, fontFace: SANS, fontSize: 13.5, bold: true, color: "FFFFFF", margin: 0 }
  );

  footer(s, 10, "SIROS Foundation  ·  Stockholm  ·  info@siros.org");
  s.addNotes("Close on reuse: the invitation is for other schemes to run the same pipeline rather than to depend on ours.");
}

pres.writeFile({ fileName: "siros-trust-infrastructure.pptx" }).then(() => {
  console.log("written", fs.statSync("siros-trust-infrastructure.pptx").size, "bytes");
});

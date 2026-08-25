/*
 * SIROS trust infrastructure deck.
 *
 * Visual language is lifted from siros.org: design tokens from src/index.css,
 * card / icon-chip treatment from SolutionCard.tsx, Lucide icons, and the
 * Helvetica Neue -> Arial type stack from tailwind.config.ts.
 */
const pptxgen = require("pptxgenjs");
const sharp = require("sharp");
const fs = require("fs");
const { icon } = require("./icons");

/* ── siros.org design tokens (hsl -> hex) ──────────────────────────────── */
const FG = "121721";        // --foreground         220 30% 10%
const CARD = "F6F7F9";      // --card               210 20% 97%
const BORDER = "DCE1E5";    // --border             210 15% 88%
const ACCENT = "295CA3";    // --primary / --accent 215 60% 40%
const ACCENT_HI = "2866BD"; // mid-point of .text-gradient-light
const MUTED_FG = "5C6270";  // --muted-foreground   220 10% 40%
const MUTED = "F1F3F4";     // --muted              210 15% 95%
const TINT = "EAEFF6";      // bg-primary/10 over white
const WHITE = "FFFFFF";

const FONT = "Arial";       // "Helvetica Neue", Arial, system-ui
const RADIUS = 0.12;        // --radius: 0.75rem

const W = 13.333, H = 7.5;
const M = 0.7;
const CW = W - 2 * M;
const LOGO = "siros-logo.png";
const HERO = "hero-faded.png";

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.author = "SIROS Foundation";
pres.company = "SIROS Foundation";
pres.title = "SIROS Trust Infrastructure";

/* ── primitives ────────────────────────────────────────────────────────── */

function newSlide(opts = {}) {
  const s = pres.addSlide();
  s.background = opts.background || { color: WHITE };
  s.addImage({ path: LOGO, x: W - M - 1.7, y: 0.36, w: 1.7, h: 0.567 });
  return s;
}

// h2 + muted lead: the siros.org section-header pattern
function heading(s, title, lead) {
  s.addText(title, {
    x: M, y: 0.5, w: 9.5, h: 0.55, fontFace: FONT, fontSize: 30, bold: true,
    color: ACCENT_HI, margin: 0, valign: "top",
  });
  if (lead) {
    s.addText(lead, {
      x: M, y: 1.12, w: CW, h: 0.6, fontFace: FONT, fontSize: 13,
      color: MUTED_FG, margin: 0, valign: "top", lineSpacing: 19,
    });
  }
}

// rounded-lg border border-border bg-card
function card(s, x, y, w, h, opts = {}) {
  s.addShape(pres.ShapeType.roundRect, {
    x, y, w, h, rectRadius: RADIUS,
    fill: { color: opts.fill || CARD },
    line: { color: opts.line || BORDER, width: 1 },
  });
}

// w-12 h-12 rounded-lg bg-primary/10 text-primary  (SolutionCard)
async function chip(s, x, y, name, opts = {}) {
  const d = opts.d || 0.5;
  s.addShape(pres.ShapeType.roundRect, {
    x, y, w: d, h: d, rectRadius: RADIUS * 0.75,
    fill: { color: opts.fill || TINT },
    line: { color: opts.fill || TINT, width: 0 },
  });
  const g = d * 0.54;
  s.addImage({
    data: await icon(name, opts.color || ACCENT),
    x: x + (d - g) / 2, y: y + (d - g) / 2, w: g, h: g,
  });
}

function footer(s, n, text) {
  s.addShape(pres.ShapeType.line, {
    x: M, y: H - 0.78, w: CW, h: 0, line: { color: BORDER, width: 1 },
  });
  s.addText(text, {
    x: M, y: H - 0.68, w: 10.4, h: 0.32, fontFace: FONT, fontSize: 9.5,
    color: MUTED_FG, margin: 0, valign: "middle",
  });
  s.addText(String(n), {
    x: W - M - 0.6, y: H - 0.68, w: 0.6, h: 0.32, align: "right", margin: 0,
    fontFace: FONT, fontSize: 9.5, color: MUTED_FG, valign: "middle",
  });
}

const bullets = (lines) =>
  lines.map((t, j) => ({
    text: t,
    options: { bullet: { indent: 12 }, breakLine: j < lines.length - 1 },
  }));

/* ── hero background: the site hero image, faded into the page ────────── */
async function buildHero() {
  const w = 2000, h = 1125;
  const img = await sharp("hero-bg.jpg")
    .resize(w, h, { fit: "cover" })
    .flatten({ background: "#ffffff" })
    .toBuffer();
  const veil = Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}">
       <defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
         <stop offset="0%"   stop-color="#ffffff" stop-opacity="0.88"/>
         <stop offset="38%"  stop-color="#ffffff" stop-opacity="0.96"/>
         <stop offset="55%"  stop-color="#ffffff" stop-opacity="1"/>
         <stop offset="100%" stop-color="#ffffff" stop-opacity="1"/>
       </linearGradient></defs>
       <rect width="${w}" height="${h}" fill="url(#g)"/>
     </svg>`
  );
  await sharp(img).composite([{ input: veil }]).png().toFile(HERO);
}

/* ── deck ──────────────────────────────────────────────────────────────── */
async function main() {
  await buildHero();

  /* 1 ─ hero */
  {
    const s = newSlide({ background: { path: HERO } });
    s.addText(
      [
        { text: "Trust Lists\n", options: { color: ACCENT_HI } },
        { text: "For The EUDI Wallet Ecosystem", options: { color: FG } },
      ],
      { x: M, y: 1.5, w: 9.6, h: 1.9, fontFace: FONT, fontSize: 42, bold: true, lineSpacing: 50, margin: 0 }
    );
    s.addText(
      "Standards-based, PR-governed and HSM-signed trust anchors — from source data in Git " +
      "to signed ETSI documents on the public web.",
      { x: M, y: 3.5, w: 8.6, h: 0.7, fontFace: FONT, fontSize: 15, color: FG, margin: 0, lineSpacing: 23 }
    );

    const chips = [
      ["LuFileCode", "g119612", "Library and tsl-tool"],
      ["LuGitPullRequest", "trust-lists", "Source data and CI"],
      ["LuGlobe", "trust.siros.org", "Published lists"],
    ];
    for (let i = 0; i < chips.length; i++) {
      const [ic, t, sub] = chips[i];
      const x = M + i * 4.06;
      card(s, x, 4.5, 3.82, 1.5);
      await chip(s, x + 0.32, 4.74, ic, { d: 0.46 });
      s.addText(t, {
        x: x + 0.9, y: 4.74, w: 2.75, h: 0.46, valign: "middle", margin: 0,
        fontFace: FONT, fontSize: 15, bold: true, color: FG,
      });
      s.addText(sub, {
        x: x + 0.32, y: 5.34, w: 3.2, h: 0.3, fontFace: FONT, fontSize: 11.5,
        color: MUTED_FG, margin: 0,
      });
    }

    s.addText("SIROS Foundation   ·   ETSI TS 119 612   ·   ETSI TS 119 602   ·   BSD-2-Clause", {
      x: M, y: H - 0.78, w: 10.4, h: 0.32, fontFace: FONT, fontSize: 10,
      color: MUTED_FG, margin: 0,
    });
    s.addNotes(
      "Three artefacts, one story: g119612 is the engine, trust-lists is the governed source of truth, " +
      "trust.siros.org is the published, signed output that wallets and verifiers consume."
    );
  }

  /* 2 ─ the problem */
  {
    const s = newSlide();
    heading(s, "Who Is Authorised To Do What?",
      "An issuer, a wallet and a verifier each have to answer the same question about the other side: is this " +
      "counterpart recognised by the scheme? A trust list is the signed, publicly fetchable answer.");

    const actors = [
      ["LuBadgeCheck", "Issuer", "signs credentials"],
      ["LuWallet", "Wallet Unit", "holds and presents"],
      ["LuScanEye", "Verifier", "requests and checks"],
    ];
    for (let i = 0; i < actors.length; i++) {
      const [ic, t, sub] = actors[i];
      const x = M + i * 4.06;
      card(s, x, 2.06, 3.82, 1.16);
      await chip(s, x + 0.32, 2.31, ic, { d: 0.46 });
      s.addText(t, {
        x: x + 0.9, y: 2.28, w: 2.75, h: 0.28, margin: 0,
        fontFace: FONT, fontSize: 14.5, bold: true, color: FG,
      });
      s.addText(sub, {
        x: x + 0.9, y: 2.58, w: 2.8, h: 0.26, fontFace: FONT, fontSize: 11, color: MUTED_FG, margin: 0,
      });
      s.addShape(pres.ShapeType.line, {
        x: x + 1.91, y: 3.22, w: 0, h: 0.44, line: { color: BORDER, width: 1.25, dashType: "dash" },
      });
    }

    for (let i = 0; i < 2; i++) {
      s.addImage({
        data: await icon("LuArrowRight", MUTED_FG),
        x: M + i * 4.06 + 3.84, y: 2.53, w: 0.22, h: 0.22,
      });
    }

    card(s, M, 3.66, CW, 0.76, { fill: ACCENT, line: ACCENT });
    await chip(s, M + 0.3, 3.79, "LuListChecks", { d: 0.5, fill: ACCENT, color: WHITE });
    s.addText("Trust list — the shared anchor of authority", {
      x: M + 0.94, y: 3.66, w: 10.6, h: 0.76, valign: "middle", margin: 0,
      fontFace: FONT, fontSize: 15, bold: true, color: WHITE,
    });

    const stds = [
      ["LuFileCode", "ETSI TS 119 612", "Trust Status List (TSL)",
        "XML, signed with XML-DSIG / XAdES. The format the EU LOTL and the national lists already use."],
      ["LuFileJson", "ETSI TS 119 602", "List of Trusted Entities (LoTE)",
        "JSON, signed with JWS. The newer, wallet-friendly format, with LoTL for lists of lists."],
    ];
    for (let i = 0; i < stds.length; i++) {
      const [ic, spec, name, body] = stds[i];
      const x = M + i * 6.0;
      card(s, x, 4.66, 5.6, 1.56);
      await chip(s, x + 0.32, 4.9, ic, { d: 0.46 });
      s.addText(spec, {
        x: x + 0.9, y: 4.88, w: 4.4, h: 0.24, fontFace: FONT, fontSize: 10.5, bold: true,
        color: ACCENT, margin: 0,
      });
      s.addText(name, {
        x: x + 0.9, y: 5.12, w: 4.5, h: 0.28, fontFace: FONT, fontSize: 14, bold: true,
        color: FG, margin: 0,
      });
      s.addText(body, {
        x: x + 0.32, y: 5.52, w: 5.0, h: 0.56, fontFace: FONT, fontSize: 11, color: MUTED_FG,
        margin: 0, lineSpacing: 16,
      });
    }

    footer(s, 2, "Both formats are first-class here — and one converts to the other.");
    s.addNotes("The EUDI ecosystem is mid-migration: XML TSLs exist today, JSON LoTEs are where it is heading. Supporting both, and converting between them, is the point.");
  }

  /* 3 ─ the stack */
  {
    const s = newSlide();
    heading(s, "Three Repositories, One Pipeline",
      "Code, data and published output are cleanly separated, each with its own review and release cadence.");

    const items = [
      ["LuFileCode", "g119612", "The engine",
        ["Go library for TS 119 612 and TS 119 602", "tsl-tool CLI, driven by YAML pipelines", "Ships as a GitHub Action"]],
      ["LuGitPullRequest", "trust-lists", "The source of truth",
        ["Entities and providers as YAML plus certs", "Every change is a reviewed pull request", "Git history is the audit log"]],
      ["LuGlobe", "trust.siros.org", "The published output",
        ["Signed LoTE JSON and JWS, TSL XML", "Deployed to GitHub Pages on merge", "Fetched by wallets, verifiers, PDPs"]],
    ];
    for (let i = 0; i < items.length; i++) {
      const [ic, title, sub, lines] = items[i];
      const x = M + i * 4.06;
      card(s, x, 2.06, 3.82, 3.1);
      await chip(s, x + 0.32, 2.36, ic);
      s.addText(title, {
        x: x + 0.32, y: 3.16, w: 3.2, h: 0.32, fontFace: FONT, fontSize: 17, bold: true, color: FG, margin: 0,
      });
      s.addText(sub, {
        x: x + 0.32, y: 3.5, w: 3.2, h: 0.26, fontFace: FONT, fontSize: 11.5, bold: true, color: ACCENT, margin: 0,
      });
      s.addText(bullets(lines), {
        x: x + 0.32, y: 3.88, w: 3.2, h: 1.3, fontFace: FONT, fontSize: 11.5, color: MUTED_FG,
        margin: 0, paraSpaceAfter: 6, valign: "top", lineSpacing: 15,
      });
    }

    card(s, M, 5.34, CW, 0.86, { fill: MUTED, line: BORDER });
    s.addText([
      { text: "Downstream:  ", options: { bold: true, color: FG } },
      { text: "go-trust consumes the published lists as an AuthZEN Trust Decision Point — parallel evaluation across ETSI TSL, LoTE, OpenID Federation and DID Web.", options: { color: MUTED_FG } },
    ], { x: M + 0.32, y: 5.34, w: 11.3, h: 0.86, valign: "middle", fontFace: FONT, fontSize: 12, margin: 0 });

    footer(s, 3, "github.com/sirosfoundation");
    s.addNotes("Clean separation: code, data, output. Each has its own release and review cadence.");
  }

  /* 4 ─ the library */
  {
    const s = newSlide();
    heading(s, "One Library, Both ETSI Formats",
      "g119612 handles the XML and the JSON worlds side by side, and converts between them.");

    const cols = [
      ["LuFileCode", "TS 119 612 · TSL (XML)", [
        "Full parsing and structural validation",
        "XML digital signature validation",
        "Build an x509.CertPool straight from a TSL",
        "Brainpool curves via go-cryptoutil",
        "XSLT transform to browsable HTML",
      ]],
      ["LuFileJson", "TS 119 602 · LoTE (JSON)", [
        "Parse, generate, validate and publish LoTEs",
        "TSL to LoTE conversion",
        "JWS signing — file keys or PKCS#11 / HSM",
        "X.509, JWK and DID identities",
        "Merge and sequence-number management",
      ]],
    ];
    for (let i = 0; i < cols.length; i++) {
      const [ic, title, lines] = cols[i];
      const x = M + i * 6.0;
      card(s, x, 2.0, 5.6, 2.34);
      await chip(s, x + 0.32, 2.22, ic, { d: 0.46 });
      s.addText(title, {
        x: x + 0.9, y: 2.22, w: 4.5, h: 0.46, valign: "middle", margin: 0,
        fontFace: FONT, fontSize: 14, bold: true, color: FG,
      });
      s.addText(bullets(lines), {
        x: x + 0.32, y: 2.8, w: 5.0, h: 1.4, fontFace: FONT, fontSize: 11.5, color: MUTED_FG,
        margin: 0, paraSpaceAfter: 4, valign: "top",
      });
    }

    s.addText([
      { text: "Packages   ", options: { bold: true, color: FG, fontSize: 12 } },
      { text: "etsi119612 · etsi119602 · dsig · jws · pipeline · xslt · validation · resilience · logging", options: { color: MUTED_FG, fontSize: 12 } },
    ], { x: M + 0.02, y: 4.5, w: CW, h: 0.3, fontFace: FONT, margin: 0 });

    const stats = [
      ["13.1k", "lines of library code"],
      ["15.0k", "lines of tests"],
      ["Go 1.26", "reentrant, no caching"],
      ["BSD-2", "OpenSSF Scorecard tracked"],
    ];
    for (let i = 0; i < stats.length; i++) {
      const [big, label] = stats[i];
      const x = M + i * 3.02;
      card(s, x, 4.94, 2.8, 1.26);
      s.addText(big, {
        x: x + 0.28, y: 5.06, w: 2.4, h: 0.52, fontFace: FONT, fontSize: 26, bold: true,
        color: ACCENT_HI, margin: 0,
      });
      s.addText(label, {
        x: x + 0.28, y: 5.6, w: 2.4, h: 0.46, fontFace: FONT, fontSize: 10.5, color: MUTED_FG, margin: 0,
      });
    }

    footer(s, 4, "pkg.go.dev/github.com/sirosfoundation/g119612");
    s.addNotes("Deliberately unopinionated about caching and availability — fetch from a CDN, the library stays reentrant.");
  }

  /* 5 ─ pipelines */
  {
    const s = newSlide();
    heading(s, "Pipelines, Not Bespoke Scripts",
      "Every trust list is produced by a YAML pipeline that runs identically on a laptop and in CI.");

    card(s, M, 2.0, 5.6, 3.2);
    await chip(s, M + 0.32, 2.22, "LuWorkflow", { d: 0.46 });
    s.addText("pipeline.yaml", {
      x: M + 0.9, y: 2.22, w: 4.4, h: 0.46, valign: "middle", margin: 0,
      fontFace: FONT, fontSize: 13.5, bold: true, color: FG,
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
      { x: M + 0.32, y: 2.84, w: 5.05, h: 2.2, fontFace: "Courier New", fontSize: 10, color: FG, margin: 0, lineSpacing: 13 }
    );

    const groups = [
      ["LuFileCode", "TSL steps", "load · select · transform · publish · generate · generate_index · report · set-fetch-options · log"],
      ["LuFileJson", "LoTE steps", "load-lote · generate-lote · generate-lotl · convert-to-lote · merge-lote · increment-lote-sequence · publish-lote"],
    ];
    for (let i = 0; i < groups.length; i++) {
      const [ic, t, body] = groups[i];
      const y = 2.0 + i * 1.7;
      card(s, 6.72, y, 5.92, 1.5);
      await chip(s, 7.04, y + 0.22, ic, { d: 0.46 });
      s.addText(t, {
        x: 7.62, y: y + 0.22, w: 4.8, h: 0.46, valign: "middle", margin: 0,
        fontFace: FONT, fontSize: 13.5, bold: true, color: FG,
      });
      s.addText(body, {
        x: 7.04, y: y + 0.8, w: 5.3, h: 0.56, fontFace: FONT, fontSize: 11, color: MUTED_FG, margin: 0, lineSpacing: 16,
      });
    }

    card(s, M, 5.34, CW, 0.86, { fill: MUTED, line: BORDER });
    s.addText([
      { text: "Reusable in CI:  ", options: { bold: true, color: FG } },
      { text: "tsl-tool ships as a composite GitHub Action — ", options: { color: MUTED_FG } },
      { text: "uses: sirosfoundation/g119612@v0.7.0", options: { color: FG, fontFace: "Courier New" } },
      { text: " — so the same pipeline file runs locally and in the trust-lists workflows.", options: { color: MUTED_FG } },
    ], { x: M + 0.32, y: 5.34, w: 11.3, h: 0.86, valign: "middle", fontFace: FONT, fontSize: 11.5, margin: 0 });

    footer(s, 5, "One YAML file per trust list decides what that list is and how it is signed.");
    s.addNotes("The pipeline abstraction is what lets trust-lists stay pure data: each directory carries its own .pipeline.yaml.");
  }

  /* 6 ─ trust data as code */
  {
    const s = newSlide();
    heading(s, "Trust Data As Code",
      "Trust anchors live in reviewed YAML and certificate files, not in a database somebody can edit quietly.");

    card(s, M, 2.0, 5.6, 3.2);
    await chip(s, M + 0.32, 2.22, "LuFolderTree", { d: 0.46 });
    s.addText("lists/<instance>/", {
      x: M + 0.9, y: 2.22, w: 4.4, h: 0.46, valign: "middle", margin: 0,
      fontFace: FONT, fontSize: 13.5, bold: true, color: FG,
    });
    s.addText(
      ".pipeline.yaml     what this list is\n" +
      "scheme.yaml        operator, type, territory\n" +
      "lotl.yaml          pointers (lists of lists)\n" +
      "entities/          LoTE trusted entities\n" +
      "  <entity>/\n" +
      "    entity.yaml    names, entityId, services\n" +
      "    cert.pem       X.509\n" +
      "    key.jwk        JWK\n" +
      "providers/         TSL service providers\n" +
      "  <provider>/\n" +
      "    provider.yaml\n" +
      "    <service>/cert.pem + cert.yaml",
      { x: M + 0.32, y: 2.84, w: 5.05, h: 2.2, fontFace: "Courier New", fontSize: 9.5, color: FG, margin: 0, lineSpacing: 13 }
    );

    const steps = [
      ["LuGitPullRequest", "Propose", "A contributor opens a PR adding or amending an entity directory."],
      ["LuCircleCheck", "Validate", "CI runs every pipeline in validation mode — structure and certificates must parse."],
      ["LuUsers", "Review", "A human approves the change to the trust anchor set. Nothing merges unreviewed."],
      ["LuUpload", "Publish", "Merge to main rebuilds, signs and deploys the affected lists."],
    ];
    for (let i = 0; i < steps.length; i++) {
      const [ic, t, body] = steps[i];
      const y = 2.02 + i * 0.83;
      await chip(s, 6.72, y, ic, { d: 0.46 });
      s.addText([
        { text: String(i + 1).padStart(2, "0") + "   ", options: { color: ACCENT } },
        { text: t, options: { color: FG } },
      ], { x: 7.3, y: y - 0.02, w: 5.3, h: 0.26, fontFace: FONT, fontSize: 13.5, bold: true, margin: 0 });
      s.addText(body, {
        x: 7.3, y: y + 0.26, w: 5.32, h: 0.5, fontFace: FONT, fontSize: 11, color: MUTED_FG, margin: 0, lineSpacing: 15,
      });
    }

    card(s, M, 5.34, CW, 0.86, { fill: MUTED, line: BORDER });
    s.addText([
      { text: "The result:  ", options: { bold: true, color: FG } },
      { text: "every trusted entity, every certificate and every removal is attributable, reviewable and reversible in Git history.", options: { color: MUTED_FG } },
    ], { x: M + 0.32, y: 5.34, w: 11.3, h: 0.86, valign: "middle", fontFace: FONT, fontSize: 12, margin: 0 });

    footer(s, 6, "github.com/sirosfoundation/trust-lists");
    s.addNotes("The governance claim is the real product here — the file format is incidental, the review trail is not.");
  }

  /* 7 ─ signing */
  {
    const s = newSlide();
    heading(s, "Keys Never Leave The Token",
      "All signing goes through one PKCS#11 interface, so the same pipeline runs against an ephemeral CI key or a " +
      "hardware security module. Only the mode changes.");

    const modes = [
      ["LuCpu", "dev", "Ephemeral SoftHSM", "New key every build", "GitHub-hosted runner", "CI testing, quick validation"],
      ["LuHardDrive", "softhsm", "Persistent SoftHSM2", "Token pinned to the host", "Self-hosted runner", "Staging, pre-production"],
      ["LuKeyRound", "yubihsm", "YubiHSM 2", "Hardware-held key", "Self-hosted runner", "Production"],
    ];
    for (let i = 0; i < modes.length; i++) {
      const [ic, mode, kind, persist, runner, use] = modes[i];
      const x = M + i * 4.06;
      card(s, x, 2.06, 3.82, 2.86, i === 2 ? { fill: TINT, line: "C9D8EC" } : {});
      await chip(s, x + 0.32, 2.3, ic, { d: 0.46, fill: i === 2 ? WHITE : TINT });
      s.addText(mode, {
        x: x + 0.9, y: 2.3, w: 2.75, h: 0.46, valign: "middle", margin: 0,
        fontFace: "Courier New", fontSize: 15, bold: true, color: ACCENT,
      });
      s.addText(kind, {
        x: x + 0.32, y: 2.88, w: 3.25, h: 0.3, fontFace: FONT, fontSize: 13, bold: true, color: FG, margin: 0,
      });
      [["Key", persist], ["Runner", runner], ["Use", use]].forEach(([k, v], j) => {
        s.addText([
          { text: k + "   ", options: { bold: true, color: FG } },
          { text: v, options: { color: MUTED_FG } },
        ], { x: x + 0.32, y: 3.3 + j * 0.5, w: 3.25, h: 0.44, fontFace: FONT, fontSize: 10.5, margin: 0 });
      });
    }

    const notes = [
      ["LuSignature", "LoTE to JWS", "JSON lists are signed as JSON Web Signatures alongside the unsigned document."],
      ["LuFileCode", "TSL to XML-DSIG", "XML lists carry an enveloped XAdES signature."],
      ["LuShieldCheck", "Verified in CI", "The workflow proves signing certificate and key match before it publishes anything."],
    ];
    for (let i = 0; i < notes.length; i++) {
      const [ic, t, body] = notes[i];
      const x = M + i * 4.06;
      await chip(s, x, 5.18, ic, { d: 0.42 });
      s.addText(t, {
        x: x + 0.54, y: 5.18, w: 3.28, h: 0.42, valign: "middle", margin: 0,
        fontFace: FONT, fontSize: 12.5, bold: true, color: FG,
      });
      s.addText(body, {
        x: x, y: 5.7, w: 3.7, h: 0.6, fontFace: FONT, fontSize: 10.5, color: MUTED_FG, margin: 0, lineSpacing: 15,
      });
    }

    footer(s, 7, "A scheduled workflow reissues the signing certificate before it expires.");
    s.addNotes("Signing mode is a repository variable, so promoting from dev to hardware is a configuration change, not a code change.");
  }

  /* 8 ─ what is live */
  {
    const s = newSlide();
    heading(s, "What Is Live Today",
      "Six trust lists are built and signed from this repository on every merge to main.");

    const rows = [
      ["siros-demo", "LoTE", "Demo scheme — SIROS Identity Credential Issuer"],
      ["siros-demo-lotl", "LoTL", "List of trusted lists, pointing at the demo LoTE"],
      ["multipaz.org", "LoTE", "Verifier entity for the multipaz.org ecosystem"],
      ["digital-credentials.dev", "LoTE", "Verifier entity for digital-credentials.dev"],
      ["siros-multipaz-verifier", "LoTE", "SIROS-hosted multipaz-ppid verifier"],
      ["ewc-demo", "TSL to LoTE", "EWC Consortium demo — 17 trust service providers"],
    ];

    const tw = 9.4, y0 = 2.02, rh = 0.48;
    s.addText("Trust list", { x: M + 0.32, y: y0, w: 3.0, h: 0.3, fontFace: FONT, fontSize: 10, bold: true, color: MUTED_FG, margin: 0, valign: "middle" });
    s.addText("Type", { x: M + 3.5, y: y0, w: 1.5, h: 0.3, fontFace: FONT, fontSize: 10, bold: true, color: MUTED_FG, margin: 0, valign: "middle" });
    s.addText("Content", { x: M + 5.1, y: y0, w: 4.0, h: 0.3, fontFace: FONT, fontSize: 10, bold: true, color: MUTED_FG, margin: 0, valign: "middle" });
    s.addShape(pres.ShapeType.line, { x: M, y: y0 + 0.34, w: tw, h: 0, line: { color: BORDER, width: 1 } });

    rows.forEach(([name, type, desc], i) => {
      const y = y0 + 0.4 + i * rh;
      if (i % 2 === 0) card(s, M, y, tw, rh - 0.05, { fill: CARD, line: CARD });
      s.addText(name, { x: M + 0.32, y, w: 3.2, h: rh - 0.05, valign: "middle", margin: 0, fontFace: "Courier New", fontSize: 11, bold: true, color: FG });
      s.addText(type, { x: M + 3.5, y, w: 1.6, h: rh - 0.05, valign: "middle", margin: 0, fontFace: FONT, fontSize: 10.5, bold: true, color: ACCENT });
      s.addText(desc, { x: M + 5.1, y, w: 4.1, h: rh - 0.05, valign: "middle", margin: 0, fontFace: FONT, fontSize: 10.5, color: MUTED_FG });
    });

    card(s, 10.36, y0, 2.28, 3.2);
    await chip(s, 10.66, y0 + 0.24, "LuDatabase", { d: 0.44 });
    s.addText("Per list", {
      x: 10.66, y: y0 + 0.82, w: 1.8, h: 0.28, fontFace: FONT, fontSize: 12.5, bold: true, color: FG, margin: 0,
    });
    s.addText(bullets([".json  unsigned", ".json.jws  signed", ".xml  XML form"]), {
      x: 10.66, y: y0 + 1.16, w: 1.75, h: 0.9, fontFace: FONT, fontSize: 10.5, color: MUTED_FG,
      margin: 0, paraSpaceAfter: 6, valign: "top",
    });
    s.addText("Plus a generated index.html listing every artefact.", {
      x: 10.66, y: y0 + 2.24, w: 1.75, h: 0.8, fontFace: FONT, fontSize: 10.5, color: MUTED_FG, margin: 0, lineSpacing: 14,
    });

    card(s, M, 5.42, CW, 0.78, { fill: MUTED, line: BORDER });
    s.addText([
      { text: "Distribution points are stable URLs — ", options: { color: MUTED_FG } },
      { text: "https://trust.siros.org/<instance>.json", options: { fontFace: "Courier New", color: FG } },
      { text: " — served from GitHub Pages and referenced from the scheme metadata itself.", options: { color: MUTED_FG } },
    ], { x: M + 0.32, y: 5.42, w: 11.3, h: 0.78, valign: "middle", fontFace: FONT, fontSize: 11.5, margin: 0 });

    footer(s, 8, "trust.siros.org");
    s.addNotes("The mix is deliberate: demo schemes to exercise the tooling, plus real interop targets like EWC and multipaz.");
  }

  /* 9 ─ end to end */
  {
    const s = newSlide();
    heading(s, "From Pull Request To Trust Anchor",
      "No step in this chain is manual, and no step is unrecorded.");

    const flow = [
      ["LuGitPullRequest", "Pull request", "An entity is added, amended or withdrawn under lists/."],
      ["LuCircleCheck", "Validation", "CI runs each pipeline with tsl-tool; malformed data never merges."],
      ["LuGitMerge", "Review and merge", "A maintainer approves; main becomes the new state of the world."],
      ["LuSignature", "Build and sign", "Pipelines regenerate every list and sign via PKCS#11 — JWS or XAdES."],
      ["LuUpload", "Publish", "Artefacts and a fresh index deploy to GitHub Pages at trust.siros.org."],
      ["LuScanEye", "Consume", "Wallets, verifiers and go-trust fetch the list and build a certificate pool."],
    ];
    for (let i = 0; i < flow.length; i++) {
      const [ic, t, body] = flow[i];
      const col = i % 3, row = Math.floor(i / 3);
      const x = M + col * 4.06, y = 2.2 + row * 2.06;
      card(s, x, y, 3.82, 1.82);
      await chip(s, x + 0.32, y + 0.26, ic, { d: 0.46 });
      s.addText([
        { text: String(i + 1).padStart(2, "0") + "   ", options: { color: ACCENT } },
        { text: t, options: { color: FG } },
      ], { x: x + 0.9, y: y + 0.26, w: 2.8, h: 0.46, valign: "middle", margin: 0, fontFace: FONT, fontSize: 13.5, bold: true });
      s.addText(body, {
        x: x + 0.32, y: y + 0.84, w: 3.2, h: 0.62, fontFace: FONT, fontSize: 11, color: MUTED_FG, margin: 0, lineSpacing: 15,
      });
    }
    for (const [x, y] of [[M + 3.84, 3.0], [M + 7.9, 3.0], [M + 3.84, 5.06], [M + 7.9, 5.06]]) {
      s.addImage({ data: await icon("LuArrowRight", MUTED_FG), x, y, w: 0.22, h: 0.22 });
    }

    footer(s, 9, "Minutes from merge to a signed list on the public web.");
    s.addNotes("Worth stressing that steps 4 and 5 are the same code contributors run locally — no bespoke publishing machinery.");
  }

  /* 10 ─ summary */
  {
    const s = newSlide();
    heading(s, "Why Build It This Way",
      "Open formats, open code, and a governance trail anyone can audit.");

    const points = [
      ["LuFileCheck", "Standards first", "Nothing proprietary in the wire formats: ETSI TS 119 612 and TS 119 602, verifiable by any conforming implementation."],
      ["LuListChecks", "Auditable by construction", "Trust anchors live in reviewed YAML, and every change to the anchor set is attributable in Git."],
      ["LuKeyRound", "Hardware-backed", "One PKCS#11 path from laptop to YubiHSM; the production key never leaves the token."],
      ["LuPlug", "Reusable", "g119612 is an independent BSD-2 library — the pipeline works for anyone's trust list, not just ours."],
    ];
    for (let i = 0; i < points.length; i++) {
      const [ic, t, body] = points[i];
      const col = i % 2, row = Math.floor(i / 2);
      const x = M + col * 6.0, y = 2.06 + row * 1.62;
      card(s, x, y, 5.6, 1.36);
      await chip(s, x + 0.32, y + 0.24, ic, { d: 0.46 });
      s.addText(t, {
        x: x + 0.9, y: y + 0.24, w: 4.4, h: 0.46, valign: "middle", margin: 0,
        fontFace: FONT, fontSize: 14.5, bold: true, color: FG,
      });
      s.addText(body, {
        x: x + 0.32, y: y + 0.8, w: 5.0, h: 0.5, fontFace: FONT, fontSize: 11, color: MUTED_FG, margin: 0, lineSpacing: 15,
      });
    }

    // the one solid-accent element siros.org uses: a primary button
    card(s, M, 5.32, CW, 0.9, { fill: ACCENT, line: ACCENT });
    s.addText([
      { text: "Explore   ", options: { color: "BBD0EA" } },
      { text: "trust.siros.org   ·   github.com/sirosfoundation/trust-lists   ·   github.com/sirosfoundation/g119612", options: { color: WHITE } },
    ], { x: M + 0.32, y: 5.32, w: 11.3, h: 0.9, valign: "middle", fontFace: FONT, fontSize: 13.5, bold: true, margin: 0 });

    footer(s, 10, "SIROS Foundation   ·   Bredgränd 4, 111 30 Stockholm, Sweden   ·   info@siros.org");
    s.addNotes("Close on reuse: the invitation is for other schemes to run the same pipeline rather than to depend on ours.");
  }

  await pres.writeFile({ fileName: "siros-trust-infrastructure.pptx" });
  console.log("written", fs.statSync("siros-trust-infrastructure.pptx").size, "bytes");
}

main().catch((e) => { console.error(e); process.exit(1); });

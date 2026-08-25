// Render Lucide icons (the icon pack siros.org uses) to base64 PNG for pptxgenjs.
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const lu = require("react-icons/lu");
const sharp = require("sharp");

const cache = new Map();

async function icon(name, color = "295CA3", px = 256) {
  const key = `${name}:${color}:${px}`;
  if (cache.has(key)) return cache.get(key);
  const Cmp = lu[name];
  if (!Cmp) throw new Error(`unknown lucide icon: ${name}`);
  let svg = ReactDOMServer.renderToStaticMarkup(
    React.createElement(Cmp, { size: px, color: `#${color}`, strokeWidth: 2 })
  );
  if (!svg.includes("xmlns=")) svg = svg.replace("<svg", '<svg xmlns="http://www.w3.org/2000/svg"');
  const buf = await sharp(Buffer.from(svg)).resize(px, px).png().toBuffer();
  const data = "image/png;base64," + buf.toString("base64");
  cache.set(key, data);
  return data;
}

module.exports = { icon };

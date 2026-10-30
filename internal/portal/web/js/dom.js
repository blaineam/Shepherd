// Tiny DOM helpers. Every value from the network goes in via textContent.
export const $ = (s, root = document) => root.querySelector(s);

export function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// The ashgrove lib/util.js deepMerge shape: recurses over keys of source and
// writes into target[key] with no __proto__/constructor guard.
function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    const value = source[key];
    if (isPlainObject(value)) {
      // ruleid: trojan-js-prototype-pollution
      if (!isPlainObject(target[key])) target[key] = {};
      deepMerge(target[key], value);
    } else {
      // ruleid: trojan-js-prototype-pollution
      target[key] = value;
    }
  }
  return target;
}

// for..in variant, still unguarded.
function mergeIn(dst, src) {
  for (const k in src) {
    if (src[k] && typeof src[k] === "object") {
      // ruleid: trojan-js-prototype-pollution
      mergeIn(dst[k] || (dst[k] = {}), src[k]);
    } else {
      // ruleid: trojan-js-prototype-pollution
      dst[k] = src[k];
    }
  }
  return dst;
}

// Guarded merge: skips the polluting keys -> safe.
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    const value = source[key];
    if (value && typeof value === "object") {
      if (!target[key]) target[key] = {};
      safeMerge(target[key], value);
    } else {
      // ok: trojan-js-prototype-pollution
      target[key] = value;
    }
  }
  return target;
}

module.exports = { deepMerge, mergeIn, safeMerge };

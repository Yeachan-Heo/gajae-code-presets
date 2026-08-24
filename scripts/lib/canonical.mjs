import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

function assertUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) throw new TypeError("Canonical JSON rejects lone high surrogates");
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("Canonical JSON rejects lone low surrogates");
    }
  }
}

function serialize(value, stack) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON rejects non-finite numbers");
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (typeof value === "string") {
    assertUnicode(value);
    return JSON.stringify(value);
  }
  if (typeof value !== "object") throw new TypeError(`Canonical JSON rejects ${typeof value}`);
  if (stack.has(value)) throw new TypeError("Canonical JSON rejects cycles");
  stack.add(value);
  try {
    if (Array.isArray(value)) {
      const entries = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) throw new TypeError("Canonical JSON rejects sparse arrays");
        entries.push(serialize(value[index], stack));
      }
      return `[${entries.join(",")}]`;
    }
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
      throw new TypeError("Canonical JSON accepts plain objects only");
    }
    const entries = [];
    for (const key of Object.keys(value).sort()) {
      assertUnicode(key);
      entries.push(`${JSON.stringify(key)}:${serialize(value[key], stack)}`);
    }
    return `{${entries.join(",")}}`;
  } finally {
    stack.delete(value);
  }
}

export function canonicalStringify(value) {
  return serialize(value, new Set());
}

export function canonicalBytes(value) {
  return Buffer.from(canonicalStringify(value), "utf8");
}

export function canonicalWrite(filename, value) {
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  fs.writeFileSync(filename, canonicalBytes(value));
}

export function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

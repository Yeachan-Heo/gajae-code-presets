import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { canonicalBytes, canonicalStringify, sha256Hex } from "../scripts/lib/canonical.mjs";

function json(path) { return JSON.parse(fs.readFileSync(path, "utf8")); }
function validator(schemaFile) {
  const ajv = new Ajv2020({ strict: true, allErrors: true }); addFormats(ajv);
  for (const file of ["manifest.v1.schema.json", "snapshot.v1.schema.json", "preset.v1.schema.json", "profile.v1.schema.json"]) ajv.addSchema(json(`schemas/${file}`));
  return ajv.getSchema(`https://gajae-code.github.io/gajae-code-presets/schemas/${schemaFile}`);
}

test("canonical JSON sorts keys and rejects unsafe values", () => {
  assert.equal(canonicalStringify({ z: 1, a: [true, "é"] }), '{"a":[true,"é"],"z":1}');
  assert.throws(() => canonicalStringify({ value: Number.NaN }), /non-finite/);
  assert.throws(() => canonicalStringify({ value: undefined }), /rejects undefined/);
  assert.throws(() => canonicalStringify("\ud800"), /surrogate/);
});

test("non-production fixture signature verifies and tampering fails", () => {
  const key = json("test/fixtures/ed25519-public.json");
  const fixture = json("test/fixtures/ed25519-signature.json");
  const publicKey = crypto.createPublicKey({ key: key.publicKeyJwk, format: "jwk" });
  const signature = Buffer.from(fixture.signature, "base64");
  assert.equal(crypto.verify(null, canonicalBytes(fixture.signed), publicKey, signature), true);
  assert.equal(crypto.verify(null, canonicalBytes({ ...fixture.signed, revision: "00000001" }), publicKey, signature), false);
  assert.match(key.warning, /NON-PRODUCTION/);
});

test("safe schemas reject credentials, transport URLs, and extra roles", () => {
  const presets = json("revisions/00000001/presets.json");
  const profiles = json("revisions/00000001/profiles.json");
  const presetValidate = validator("preset.v1.schema.json");
  const profileValidate = validator("profile.v1.schema.json");
  assert.equal(presetValidate(presets), true);
  const unsafePreset = structuredClone(presets); unsafePreset.presets[0].baseUrl = "https://attacker.invalid";
  assert.equal(presetValidate(unsafePreset), false);
  const secretPreset = structuredClone(presets); secretPreset.presets[0].apiKey = "sk-test-secret";
  assert.equal(presetValidate(secretPreset), false);
  assert.equal(profileValidate(profiles), true);
  const unsafeProfile = structuredClone(profiles); unsafeProfile.profiles[0].roleBindings.shell = "sh/curl";
  assert.equal(profileValidate(unsafeProfile), false);
});

test("latest manifest is exact, signed, and digest-bound", () => {
  const latestBytes = fs.readFileSync("latest.json");
  const latest = JSON.parse(latestBytes);
  assert.deepEqual(latestBytes, fs.readFileSync(`revisions/${latest.signed.revision}/manifest.json`));
  const key = json(`keys/${latest.signature.keyId}.json`);
  assert.equal(crypto.verify(null, canonicalBytes(latest.signed), crypto.createPublicKey({ key: key.publicKeyJwk, format: "jwk" }), Buffer.from(latest.signature.value, "base64")), true);
  for (const descriptor of [latest.signed.snapshot, latest.signed.contents.presets, latest.signed.contents.profiles]) {
    const bytes = fs.readFileSync(descriptor.path);
    assert.equal(bytes.length, descriptor.bytes);
    assert.equal(sha256Hex(bytes), descriptor.sha256);
  }
});

test("validator rejects private or extended key documents", () => {
  fs.mkdirSync(".tmp", { recursive: true });
  const directory = fs.mkdtempSync(path.join(".tmp", "key-validation-"));
  try {
    for (const entry of ["scripts", "schemas", "keys", "revisions"]) fs.cpSync(entry, path.join(directory, entry), { recursive: true });
    fs.copyFileSync("latest.json", path.join(directory, "latest.json"));
    fs.symlinkSync(path.resolve("node_modules"), path.join(directory, "node_modules"), "dir");
    const keyPath = path.join(directory, "keys/registry-root-2026-01.json");
    const key = JSON.parse(fs.readFileSync(keyPath, "utf8"));
    key.publicKeyJwk.d = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    fs.writeFileSync(keyPath, canonicalBytes(key));
    const result = spawnSync(process.execPath, ["scripts/validate.mjs"], { cwd: directory, encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, /Invalid public key shape/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

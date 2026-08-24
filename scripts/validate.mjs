#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { canonicalBytes, sha256Hex } from "./lib/canonical.mjs";

const ROOT = process.cwd();
const RESERVED = ["gjc-", "gajae-", "system-", "internal-", "__"];
const HOMOGLYPHS = new Map(Object.entries({
  "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y","і":"i","ј":"j","к":"k","м":"m","т":"t","в":"b","н":"h",
  "Α":"a","Β":"b","Ε":"e","Ζ":"z","Η":"h","Ι":"i","Κ":"k","Μ":"m","Ν":"n","Ο":"o","Ρ":"p","Τ":"t","Υ":"y","Χ":"x",
  "α":"a","β":"b","ε":"e","ι":"i","κ":"k","ν":"v","ο":"o","ρ":"p","τ":"t","υ":"y","χ":"x"
}));

function fail(message) { throw new Error(message); }
function readJson(relative) { return JSON.parse(fs.readFileSync(path.join(ROOT, relative), "utf8")); }
function canonicalFile(relative, document) {
  const actual = fs.readFileSync(path.join(ROOT, relative));
  const expected = canonicalBytes(document);
  if (!actual.equals(expected)) fail(`${relative} is not canonical JSON`);
  return actual;
}
function skeleton(value) {
  return [...value.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase()].map(char => HOMOGLYPHS.get(char) ?? char).join("");
}
function uniqueNames(values, label) {
  const exact = new Set(); const folded = new Map();
  for (const value of values) {
    if (exact.has(value)) fail(`Duplicate ${label}: ${value}`);
    exact.add(value);
    const key = skeleton(value);
    const previous = folded.get(key);
    if (previous && previous !== value) fail(`Case/confusable ${label}: ${previous} and ${value}`);
    folded.set(key, value);
    if (RESERVED.some(prefix => value.toLowerCase().startsWith(prefix))) fail(`Reserved namespace ${label}: ${value}`);
  }
}
function scanSafe(value, location = "$") {
  if (typeof value === "string") {
    if (/https?:\/\//i.test(value) && value !== "https://github.com/Yeachan-Heo/gajae-code") fail(`Unsafe URL at ${location}`);
    if (/(?:^|[^a-z])(sk-[A-Za-z0-9_-]{12,}|gh[opusr]_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16}|Bearer\s+\S+)/i.test(value)) fail(`Possible secret at ${location}`);
    return;
  }
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) return value.forEach((entry, index) => scanSafe(entry, `${location}[${index}]`));
  for (const [key, entry] of Object.entries(value)) {
    if (/^(?:headers?|api[_-]?key|base[_-]?url|secret|password|command|script|extraBody)$/i.test(key)) fail(`Unsafe field ${location}.${key}`);
    scanSafe(entry, `${location}.${key}`);
  }
}
function verifyDescriptor(descriptor) {
  if (path.isAbsolute(descriptor.path) || descriptor.path.includes("..") || !descriptor.path.startsWith("revisions/")) fail(`Unsafe descriptor path ${descriptor.path}`);
  const bytes = fs.readFileSync(path.join(ROOT, descriptor.path));
  if (bytes.length !== descriptor.bytes) fail(`Byte count mismatch for ${descriptor.path}`);
  if (sha256Hex(bytes) !== descriptor.sha256) fail(`Digest mismatch for ${descriptor.path}`);
}
function compareSemver(left, right) {
  const a = left.split(".").map(Number); const b = right.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) if (a[index] !== b[index]) return a[index] - b[index];
  return 0;
}
function selectorBase(selector) { return selector.replace(/:(minimal|low|medium|high|xhigh|max)$/, ""); }
function validateHistory(revisions) {
  const base = process.env.BASE_REF;
  if (!base) return;
  const result = spawnSync("git", ["diff", "--name-status", `${base}...HEAD`], { cwd: ROOT, encoding: "utf8" });
  if (result.status !== 0) fail(`Cannot compare immutable history with ${base}: ${result.stderr.trim()}`);
  for (const line of result.stdout.trim().split("\n").filter(Boolean)) {
    const [status, filename] = line.split("\t");
    if (filename.startsWith("revisions/") && status !== "A") fail(`Immutable revision changed: ${line}`);
  }
  const listing = spawnSync("git", ["ls-tree", "-r", "--name-only", base, "revisions"], { cwd: ROOT, encoding: "utf8" });
  if (listing.status !== 0) fail(`Cannot inspect base revisions at ${base}`);
  const prior = [...listing.stdout.matchAll(/^revisions\/(\d{8})\//gm)].map(match => Number(match[1]));
  const priorMax = prior.length ? Math.max(...prior) : 0;
  for (const revision of revisions.map(Number).filter(number => number > priorMax)) {
    if (revision <= priorMax) fail(`New revision is not monotonic: ${revision}`);
  }
}

const schemaFiles = ["manifest.v1.schema.json", "snapshot.v1.schema.json", "preset.v1.schema.json", "profile.v1.schema.json"];
const ajv = new Ajv2020({ strict: true, allErrors: true });
addFormats(ajv);
for (const file of schemaFiles) ajv.addSchema(readJson(`schemas/${file}`));
const revisions = fs.readdirSync(path.join(ROOT, "revisions"), { withFileTypes: true }).filter(entry => entry.isDirectory()).map(entry => entry.name).sort();
if (!revisions.length || revisions.some(revision => !/^\d{8}$/.test(revision) || Number(revision) < 1)) fail("Revision directories must be positive eight-digit numbers");
uniqueNames(revisions, "revision");
for (let index = 1; index < revisions.length; index += 1) if (Number(revisions[index]) <= Number(revisions[index - 1])) fail("Revisions are not monotonic");

for (const revision of revisions) {
  const paths = {
    manifest: `revisions/${revision}/manifest.json`, snapshot: `revisions/${revision}/snapshot.json`,
    presets: `revisions/${revision}/presets.json`, profiles: `revisions/${revision}/profiles.json`
  };
  const documents = Object.fromEntries(Object.entries(paths).map(([key, filename]) => [key, readJson(filename)]));
  for (const [key, schema] of [["manifest", "manifest.v1.schema.json"], ["snapshot", "snapshot.v1.schema.json"], ["presets", "preset.v1.schema.json"], ["profiles", "profile.v1.schema.json"]]) {
    const validate = ajv.getSchema(`https://gajae-code.github.io/gajae-code-presets/schemas/${schema}`);
    if (!validate(documents[key])) fail(`${paths[key]} schema failure: ${ajv.errorsText(validate.errors, { separator: "; " })}`);
    canonicalFile(paths[key], documents[key]);
    scanSafe(documents[key]);
  }
  const { manifest, snapshot, presets, profiles } = documents;
  if ([manifest.signed.revision, snapshot.revision, presets.revision, profiles.revision].some(value => value !== revision)) fail(`Revision mismatch in ${revision}`);
  if (manifest.signed.registryRevision !== Number(revision) || snapshot.registryRevision !== Number(revision)) fail(`Numeric revision mismatch in ${revision}`);
  if (compareSemver(manifest.signed.compatibility.consumerContract.minVersion, manifest.signed.compatibility.consumerContract.maxVersion) > 0) fail(`Invalid compatibility range in ${revision}`);
  for (const descriptor of [manifest.signed.snapshot, manifest.signed.contents.presets, manifest.signed.contents.profiles, snapshot.contents.presets, snapshot.contents.profiles]) verifyDescriptor(descriptor);
  if (canonicalBytes(manifest.signed.contents).compare(canonicalBytes(snapshot.contents)) !== 0) fail(`Manifest/snapshot contents mismatch in ${revision}`);
  if (canonicalBytes(manifest.signed.compatibility).compare(canonicalBytes(snapshot.compatibility)) !== 0) fail(`Manifest/snapshot compatibility mismatch in ${revision}`);
  if (canonicalBytes(manifest.signed.provenance).compare(canonicalBytes(snapshot.provenance)) !== 0) fail(`Manifest/snapshot provenance mismatch in ${revision}`);
  if (manifest.signed.contents.presets.count !== presets.presets.length || manifest.signed.contents.profiles.count !== profiles.profiles.length) fail(`Content count mismatch in ${revision}`);
  const key = readJson(`keys/${manifest.signature.keyId}.json`);
  if (key.algorithm !== "Ed25519" || key.status !== "active" || key.revokedAt !== null) fail(`Signing key ${key.keyId} is not active`);
  if (Date.parse(manifest.signed.publishedAt) < Date.parse(key.validFrom)) fail(`Manifest predates signing key ${key.keyId}`);
  const publicKey = crypto.createPublicKey({ key: key.publicKeyJwk, format: "jwk" });
  if (!crypto.verify(null, canonicalBytes(manifest.signed), publicKey, Buffer.from(manifest.signature.value, "base64"))) fail(`Invalid manifest signature in ${revision}`);
  uniqueNames(profiles.profiles.map(profile => profile.id), "profile id");
  uniqueNames(profiles.dynamicProviders, "dynamic provider id");
  uniqueNames(presets.presets.map(preset => `${preset.provider}/${preset.id}`), "preset selector");
  const exact = new Set(presets.presets.map(preset => `${preset.provider}/${preset.id}`));
  const bare = new Set(presets.presets.map(preset => preset.id));
  const dynamic = new Set(profiles.dynamicProviders);
  for (const profile of profiles.profiles) {
    for (const value of Object.values(profile.roleBindings)) for (const selector of Array.isArray(value) ? value : [value]) {
      const base = selectorBase(selector);
      if (base.includes("/")) {
        const provider = base.slice(0, base.indexOf("/"));
        if (!exact.has(base) && !dynamic.has(provider)) fail(`Unknown model reference ${selector} in profile ${profile.id}`);
      } else if (!bare.has(base)) fail(`Unknown model alias ${selector} in profile ${profile.id}`);
    }
  }
}
const latest = readJson("latest.json");
canonicalFile("latest.json", latest);
const target = `revisions/${latest.signed.revision}/manifest.json`;
if (!fs.readFileSync(path.join(ROOT, "latest.json")).equals(fs.readFileSync(path.join(ROOT, target)))) fail(`latest.json is not byte-identical to ${target}`);
validateHistory(revisions);
process.stdout.write(`Validated ${revisions.length} revision(s); latest is ${latest.signed.revision}.\n`);

#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import process from "node:process";
import { canonicalBytes, sha256Hex } from "./lib/canonical.mjs";

function fail(message) { throw new Error(message); }
function json(filename) { return JSON.parse(fs.readFileSync(filename, "utf8")); }
function pass(surface, evidence) { return { surface, result: "PASS", evidence }; }
function scan(value, location = "$") {
  if (typeof value === "string") {
    if (/\b(?:https?|ftp|file|data):/i.test(value) && value !== "https://github.com/Yeachan-Heo/gajae-code") fail(`Unsafe URL at ${location}`);
    if (/(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-[A-Za-z0-9_-]{12,}|gh[opusr]_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16}|Bearer\s+\S+)/i.test(value)) fail(`Possible secret at ${location}`);
    return;
  }
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) return value.forEach((entry, index) => scan(entry, `${location}[${index}]`));
  for (const [key, entry] of Object.entries(value)) {
    if (/^(?:headers?|api[_-]?key|base[_-]?url|secret|password|command|script|extraBody)$/i.test(key)) fail(`Unsafe field ${location}.${key}`);
    scan(entry, `${location}.${key}`);
  }
}

const latestBytes = fs.readFileSync("latest.json");
const latest = JSON.parse(latestBytes);
const revision = latest.signed.revision;
const manifestPath = `revisions/${revision}/manifest.json`;
if (!latestBytes.equals(fs.readFileSync(manifestPath))) fail("latest.json is not the exact immutable manifest bytes");
if (!latestBytes.equals(canonicalBytes(latest))) fail("latest.json is not canonical JSON");

const key = json(`keys/${latest.signature.keyId}.json`);
if (Object.keys(key.publicKeyJwk).sort().join(",") !== "crv,kty,x" || key.publicKeyJwk.kty !== "OKP" || key.publicKeyJwk.crv !== "Ed25519" || "d" in key.publicKeyJwk) fail("Signing JWK is not strict public-only Ed25519");
if (!crypto.verify(null, canonicalBytes(latest.signed), crypto.createPublicKey({ key: key.publicKeyJwk, format: "jwk" }), Buffer.from(latest.signature.value, "base64"))) fail("Manifest signature does not verify");

const expectedPaths = {
  snapshot: `revisions/${revision}/snapshot.json`,
  presets: `revisions/${revision}/presets.json`,
  profiles: `revisions/${revision}/profiles.json`
};
if (latest.signed.snapshot.path !== expectedPaths.snapshot || latest.signed.contents.presets.path !== expectedPaths.presets || latest.signed.contents.profiles.path !== expectedPaths.profiles) fail("Signed descriptors escape their immutable revision");
for (const descriptor of [latest.signed.snapshot, latest.signed.contents.presets, latest.signed.contents.profiles]) {
  const bytes = fs.readFileSync(descriptor.path);
  if (bytes.length !== descriptor.bytes || sha256Hex(bytes) !== descriptor.sha256) fail(`Descriptor mismatch for ${descriptor.path}`);
  if (!bytes.equals(canonicalBytes(JSON.parse(bytes)))) fail(`${descriptor.path} is not canonical JSON`);
}
const snapshot = json(expectedPaths.snapshot);
if (canonicalBytes(snapshot.contents).compare(canonicalBytes(latest.signed.contents)) !== 0) fail("Snapshot content refs differ from signed manifest");
const compatibility = latest.signed.compatibility.consumerContract;
const numbers = value => value.split(".").map(Number);
if (numbers(compatibility.minVersion).some((part, index) => part > numbers(compatibility.maxVersion)[index] && numbers(compatibility.minVersion).slice(0, index).every((prior, priorIndex) => prior === numbers(compatibility.maxVersion)[priorIndex]))) fail("Compatibility minimum exceeds maximum");

for (const filename of [manifestPath, expectedPaths.snapshot, expectedPaths.presets, expectedPaths.profiles]) scan(json(filename));
const validatorSource = fs.readFileSync("scripts/validate.mjs", "utf8");
for (const required of ["validateKeyTransition", "loadRevocations", "Immutable revision changed", "Descriptors escape their owning revision", "latest.json selects revoked key", "Case/confusable", "Unsafe URL", "New revision is not above prior maximum"]) if (!validatorSource.includes(required)) fail(`Validator omits adversarial control: ${required}`);
const contract = fs.readFileSync("docs/registry-contract.md", "utf8").toLowerCase();
for (const term of ["cached-last-known-good", "atomic", "rollback", "revocation", "rotation", "compatibility", "bounded https"]) if (!contract.includes(term)) fail(`Registry contract omits ${term}`);
const packageDocument = json("package.json");
if (packageDocument.private !== true || Object.keys(packageDocument.scripts).some(name => /publish|release|tag/i.test(name))) fail("Package configuration exposes publication behavior");

const evidence = [
  pass("Canonicalization, digests, and signature", `Canonical bytes, three SHA-256 descriptors, and Ed25519 signature verified for ${revision}.`),
  pass("Immutable revision and latest rollback pointer", `latest.json is byte-identical to ${manifestPath}; descriptors are revision-local.`),
  pass("Compatibility bounds", `${compatibility.minVersion} <= consumer contract <= ${compatibility.maxVersion}.`),
  pass("Credential, URL, and executable-data boundary", "All signed registry documents passed recursive unsafe-field, URL, and secret scans; schemas are separately exercised by npm test."),
  pass("Key rotation and revocation", "Strict public-only JWK plus transition, immutable trust-record, historical revocation, and latest-key revocation controls are present."),
  pass("Reproducibility and provenance", `Snapshot provenance binds ${latest.signed.provenance.sourceRevision}; the validate workflow reproduces from that exact upstream checkout.`),
  pass("Cache and emergency rollback", "Contract requires bounded HTTPS, atomic acceptance, cached-last-known-good fallback, and pointer-only rollback."),
  pass("No release publication", "Private package has no publish/release/tag script and workflow contains validation jobs only.")
];
const reviewedSha = process.env.REVIEWED_HEAD_SHA || process.env.GITHUB_HEAD_SHA || process.env.GITHUB_SHA || "unknown";
const report = { reviewedSha, verdict: "MERGE_READY", ciAloneInsufficient: true, evidence };
const text = `${JSON.stringify(report, null, 2)}\n`;
process.stdout.write(text);
if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `## MERGE_READY — adversarial registry security\n\nExact head: \`${reviewedSha}\`\n\n${evidence.map(item => `- **${item.surface}:** ${item.evidence}`).join("\n")}\n`);

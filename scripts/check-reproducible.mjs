#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { canonicalBytes, sha256Hex } from "./lib/canonical.mjs";

const root = process.cwd();
const revisions = fs.readdirSync("revisions", { withFileTypes: true }).filter(entry => entry.isDirectory()).map(entry => entry.name).sort();
for (const revision of revisions) {
  const manifestPath = path.join("revisions", revision, "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const snapshot = JSON.parse(fs.readFileSync(manifest.signed.snapshot.path, "utf8"));
  for (const [name, descriptor] of Object.entries(snapshot.contents)) {
    const document = JSON.parse(fs.readFileSync(descriptor.path, "utf8"));
    const regenerated = canonicalBytes(document);
    const actual = fs.readFileSync(descriptor.path);
    if (!regenerated.equals(actual)) throw new Error(`${descriptor.path} does not reproduce from parsed data`);
    if (regenerated.length !== descriptor.bytes || sha256Hex(regenerated) !== descriptor.sha256) throw new Error(`${name} descriptor is not reproducible`);
  }
  const snapshotBytes = canonicalBytes(snapshot);
  if (!snapshotBytes.equals(fs.readFileSync(manifest.signed.snapshot.path))) throw new Error(`${manifest.signed.snapshot.path} is not reproducible`);
  if (snapshotBytes.length !== manifest.signed.snapshot.bytes || sha256Hex(snapshotBytes) !== manifest.signed.snapshot.sha256) throw new Error(`Snapshot descriptor is not reproducible for ${revision}`);
  if (!canonicalBytes(manifest).equals(fs.readFileSync(manifestPath))) throw new Error(`${manifestPath} is not reproducible`);
}

const upstreamSourceRoot = process.env.UPSTREAM_SOURCE_ROOT;
if (upstreamSourceRoot) {
  const latest = JSON.parse(fs.readFileSync("latest.json", "utf8"));
  const revision = latest.signed.revision;
  const temporaryRoot = path.join(root, ".tmp");
  fs.mkdirSync(temporaryRoot, { recursive: true });
  const output = fs.mkdtempSync(path.join(temporaryRoot, "reproduce-"));
  try {
    const result = spawnSync(process.execPath, [
      path.join(root, "scripts/import-upstream.mjs"),
      "--source-root", path.resolve(upstreamSourceRoot),
      "--source-revision", latest.signed.provenance.sourceRevision,
      "--source-date", latest.signed.provenance.generatedAt,
      "--revision", revision,
      "--key-id", latest.signature.keyId
    ], { cwd: output, encoding: "utf8" });
    if (result.status !== 0) throw new Error(`Upstream regeneration failed: ${result.stderr || result.stdout}`);
    for (const filename of ["presets.json", "profiles.json", "snapshot.json"]) {
      const relative = path.join("revisions", revision, filename);
      if (!fs.readFileSync(path.join(output, relative)).equals(fs.readFileSync(path.join(root, relative)))) throw new Error(`${relative} differs when regenerated from attributed upstream source`);
    }
    const generatedManifest = JSON.parse(fs.readFileSync(path.join(output, "revisions", revision, "manifest.json"), "utf8"));
    if (!canonicalBytes(generatedManifest.signed).equals(canonicalBytes(latest.signed)) || generatedManifest.schemaVersion !== latest.schemaVersion || generatedManifest.signature.algorithm !== latest.signature.algorithm || generatedManifest.signature.keyId !== latest.signature.keyId) throw new Error(`Manifest payload differs when regenerated from attributed upstream source`);
  } finally {
    fs.rmSync(output, { recursive: true, force: true });
  }
}
process.stdout.write(`Reproduced canonical bytes and digests for ${revisions.length} revision(s)${upstreamSourceRoot ? " including attributed upstream import" : ""}.\n`);

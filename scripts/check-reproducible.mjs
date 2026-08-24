#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { canonicalBytes, sha256Hex } from "./lib/canonical.mjs";

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
process.stdout.write(`Reproduced canonical bytes and digests for ${revisions.length} revision(s).\n`);

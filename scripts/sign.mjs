#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { canonicalBytes, canonicalWrite } from "./lib/canonical.mjs";

function args(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    if (!argv[index]?.startsWith("--") || !argv[index + 1]) throw new Error(`Invalid argument ${argv[index] ?? ""}`);
    values[argv[index].slice(2)] = argv[index + 1];
  }
  return values;
}

const options = args(process.argv.slice(2));
const manifestPath = path.resolve(options.manifest ?? "revisions/00000001/manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const keyPath = path.resolve(options["public-key"] ?? `keys/${manifest.signature.keyId}.json`);
const keyDocument = JSON.parse(fs.readFileSync(keyPath, "utf8"));
if (keyDocument.keyId !== manifest.signature.keyId || keyDocument.algorithm !== "Ed25519" || keyDocument.status !== "active") {
  throw new Error("Manifest key id does not name an active Ed25519 public key");
}
const privatePem = options["private-key"]
  ? fs.readFileSync(path.resolve(options["private-key"]), "utf8")
  : process.env.REGISTRY_SIGNING_PRIVATE_KEY;
if (!privatePem) throw new Error("Provide --private-key or REGISTRY_SIGNING_PRIVATE_KEY");
const privateKey = crypto.createPrivateKey(privatePem);
if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Signing key must be Ed25519");
const derived = crypto.createPublicKey(privateKey).export({ format: "jwk" });
if (derived.kty !== keyDocument.publicKeyJwk.kty || derived.crv !== keyDocument.publicKeyJwk.crv || derived.x !== keyDocument.publicKeyJwk.x) {
  throw new Error("Private key does not match the declared public key");
}
manifest.signature.value = crypto.sign(null, canonicalBytes(manifest.signed), privateKey).toString("base64");
canonicalWrite(manifestPath, manifest);
const latestPath = path.resolve(options.latest ?? "latest.json");
fs.copyFileSync(manifestPath, latestPath);
process.stdout.write(`Signed ${path.relative(process.cwd(), manifestPath)} and updated ${path.relative(process.cwd(), latestPath)}.\n`);

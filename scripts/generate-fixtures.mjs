#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalBytes, canonicalWrite } from "./lib/canonical.mjs";

const output = path.resolve(process.argv[2] ?? "test/fixtures");
const allowedRoot = path.resolve("test/fixtures");
if (output !== allowedRoot && !output.startsWith(`${allowedRoot}${path.sep}`)) throw new Error("Fixture output must stay under test/fixtures");
fs.mkdirSync(output, { recursive: true });
const seed = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
const privateKey = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
const publicKeyJwk = crypto.createPublicKey(privateKey).export({ format: "jwk" });
const privatePem = privateKey.export({ format: "pem", type: "pkcs8" });
const signed = { fixture: "NON-PRODUCTION", revision: "00000000", purpose: "Ed25519 verifier test only" };
const fixture = {
  warning: "NON-PRODUCTION TEST FIXTURE — NEVER TRUST OR USE THIS KEY FOR REGISTRY DATA",
  signed,
  signature: crypto.sign(null, canonicalBytes(signed), privateKey).toString("base64")
};
fs.writeFileSync(path.join(output, "NON_PRODUCTION_README.txt"), "NON-PRODUCTION TEST KEYS ONLY. The private key is public test material and MUST NEVER sign registry data.\n");
fs.writeFileSync(path.join(output, "ed25519-private.pem"), privatePem, { mode: 0o600 });
fs.chmodSync(path.join(output, "ed25519-private.pem"), 0o600);
canonicalWrite(path.join(output, "ed25519-public.json"), { warning: fixture.warning, algorithm: "Ed25519", keyId: "test-only-ed25519-1", publicKeyJwk });
canonicalWrite(path.join(output, "ed25519-signature.json"), fixture);
process.stdout.write(`Generated deterministic NON-PRODUCTION fixtures in ${path.relative(process.cwd(), output)}.\n`);

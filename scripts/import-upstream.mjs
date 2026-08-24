#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import ts from "typescript";
import { canonicalBytes, canonicalWrite, sha256Hex } from "./lib/canonical.mjs";

const CONTRACT_VERSION = "1.0.0";
const GENERATOR = "gajae-code-presets/scripts/import-upstream.mjs@1";
const SOURCE_REPOSITORY = "https://github.com/Yeachan-Heo/gajae-code";
const MODEL_SOURCE = "packages/ai/src/models.json";
const PROFILE_SOURCE = "packages/coding-agent/src/config/model-profiles.ts";
const SAFE_MODEL_FIELDS = [
  "id", "provider", "name", "api", "reasoning", "input", "output", "cost",
  "contextWindow", "maxTokens", "compat", "thinking", "longContextPricing",
  "applyPatchToolType", "preferWebsockets", "premiumMultiplier", "priority",
  "contextPromotionTarget"
];
const SAFE_COMPAT_FIELDS = new Set([
  "maxTokensField", "reasoningContentField", "reasoningEffortMap",
  "requiresAssistantContentForToolCalls", "requiresReasoningContentForToolCalls",
  "supportsDeveloperRole", "supportsMultipleSystemMessages", "supportsReasoningEffort",
  "supportsStore", "supportsToolChoice", "supportsUsageInStreaming", "thinkingFormat"
]);
const HOMOGLYPHS = new Map(Object.entries({
  "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y","і":"i","ј":"j","к":"k","м":"m","т":"t","в":"b","н":"h",
  "Α":"a","Β":"b","Ε":"e","Ζ":"z","Η":"h","Ι":"i","Κ":"k","Μ":"m","Ν":"n","Ο":"o","Ρ":"p","Τ":"t","Υ":"y","Χ":"x",
  "α":"a","β":"b","ε":"e","ι":"i","κ":"k","ν":"v","ο":"o","ρ":"p","τ":"t","υ":"y","χ":"x"
}));

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) fail(`Unexpected argument: ${arg}`);
    const key = arg.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) fail(`Missing value for --${key}`);
    result[key] = value;
    index += 1;
  }
  for (const key of ["source-root", "source-revision", "source-date", "revision", "key-id"]) {
    if (!result[key]) fail(`Missing required --${key}`);
  }
  if (!/^\d{8}$/.test(result.revision) || Number(result.revision) < 1) fail("--revision must be an eight-digit positive revision");
  if (!/^[0-9a-f]{40}$/.test(result["source-revision"])) fail("--source-revision must be a lowercase 40-character Git commit");
  const sourceDate = new Date(result["source-date"]);
  if (!Number.isFinite(sourceDate.valueOf()) || sourceDate.toISOString() !== result["source-date"]) {
    fail("--source-date must be canonical UTC ISO-8601, for example 2026-08-24T09:41:42.000Z");
  }
  return result;
}

function literal(node) {
  if (ts.isStringLiteralLike(node)) return node.text;
  if (ts.isNumericLiteral(node)) return Number(node.text);
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (node.kind === ts.SyntaxKind.NullKeyword) return null;
  if (ts.isArrayLiteralExpression(node)) return node.elements.map(literal);
  if (ts.isObjectLiteralExpression(node)) {
    const value = {};
    for (const property of node.properties) {
      if (!ts.isPropertyAssignment(property)) fail(`Unsupported object member in upstream profile source: ${property.getText()}`);
      const name = property.name;
      const key = ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name) ? name.text : fail(`Unsupported property name: ${name.getText()}`);
      value[key] = literal(property.initializer);
    }
    return value;
  }
  fail(`Unsupported executable expression in upstream profile source: ${node.getText()}`);
}

function findVariable(sourceFile, name) {
  for (const statement of sourceFile.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name) && declaration.name.text === name) return declaration.initializer;
    }
  }
  fail(`Cannot find ${name} in ${PROFILE_SOURCE}`);
}

function importProfiles(filename) {
  const text = fs.readFileSync(filename, "utf8");
  const source = ts.createSourceFile(filename, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const array = findVariable(source, "BUILTIN_MODEL_PROFILES");
  if (!array || !ts.isArrayLiteralExpression(array)) fail("BUILTIN_MODEL_PROFILES must be an array literal");
  const presentationNode = findVariable(source, "PROFILE_PRESENTATION");
  if (!presentationNode || !ts.isObjectLiteralExpression(presentationNode)) fail("PROFILE_PRESENTATION must be an object literal");
  const presentation = literal(presentationNode);
  const profiles = array.elements.map(element => {
    if (!ts.isCallExpression(element) || !ts.isIdentifier(element.expression) || element.expression.text !== "profile") {
      fail(`Only profile(...) calls are allowed in BUILTIN_MODEL_PROFILES: ${element.getText()}`);
    }
    const [idNode, providersNode, bindingsNode, alternativesNode] = element.arguments;
    if (!idNode || !providersNode || !bindingsNode || element.arguments.length > 4) fail(`Invalid profile call: ${element.getText()}`);
    const id = literal(idNode);
    const requiredProviders = literal(providersNode);
    const roleBindings = literal(bindingsNode);
    const alternativeProviderGroups = alternativesNode ? literal(alternativesNode) : undefined;
    const display = presentation[id];
    if (!display) fail(`Missing PROFILE_PRESENTATION entry for ${id}`);
    return {
      id,
      displayName: display.displayName,
      providerGroup: display.providerGroup,
      requiredProviders,
      ...(alternativeProviderGroups ? { alternativeProviderGroups } : {}),
      roleBindings
    };
  });
  return profiles.sort((left, right) => left.id.localeCompare(right.id, "en"));
}

function projectCompat(value) {
  if (value === undefined) return undefined;
  const projected = {};
  for (const key of Object.keys(value).sort()) {
    if (SAFE_COMPAT_FIELDS.has(key)) projected[key] = value[key];
  }
  return Object.keys(projected).length > 0 ? projected : undefined;
}

function projectPreset(raw, providerKey, modelKey) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) fail(`Invalid model ${providerKey}/${modelKey}`);
  if (raw.id !== modelKey) fail(`Model key/id mismatch at ${providerKey}/${modelKey}`);
  if (raw.provider !== providerKey) fail(`Provider key/value mismatch at ${providerKey}/${modelKey}`);
  if (raw.cost && Object.values(raw.cost).some(value => typeof value !== "number" || value < 0)) return undefined;
  const projected = {};
  for (const field of SAFE_MODEL_FIELDS) {
    if (raw[field] === undefined) continue;
    if (field === "compat") {
      const compat = projectCompat(raw.compat);
      if (compat) projected.compat = compat;
    } else {
      projected[field] = raw[field];
    }
  }
  return projected;
}

function importPresets(filename) {
  const source = JSON.parse(fs.readFileSync(filename, "utf8"));
  const presets = [];
  for (const provider of Object.keys(source).sort()) {
    const models = source[provider];
    if (!models || typeof models !== "object" || Array.isArray(models)) fail(`Invalid provider model map: ${provider}`);
    for (const modelId of Object.keys(models).sort()) {
      const preset = projectPreset(models[modelId], provider, modelId);
      if (preset) presets.push(preset);
    }
  }
  const winners = new Map();
  for (const preset of presets) {
    const selector = `${preset.provider}/${preset.id}`;
    const key = [...selector.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase()]
      .map(char => HOMOGLYPHS.get(char) ?? char).join("");
    const previous = winners.get(key);
    if (!previous) {
      winners.set(key, preset);
      continue;
    }
    const previousSelector = `${previous.provider}/${previous.id}`;
    const preferCurrent = (preset.id === preset.id.toLowerCase()) !== (previous.id === previous.id.toLowerCase())
      ? preset.id === preset.id.toLowerCase()
      : selector < previousSelector;
    if (preferCurrent) winners.set(key, preset);
  }
  return [...winners.values()].sort((left, right) => {
    const a = `${left.provider}/${left.id}`; const b = `${right.provider}/${right.id}`;
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

function descriptor(documentPath, document, count) {
  const bytes = canonicalBytes(document);
  return { path: documentPath, sha256: sha256Hex(bytes), bytes: bytes.length, count };
}

function ensureEmptyRevisionDirectory(directory) {
  if (fs.existsSync(directory)) fail(`Immutable revision already exists: ${directory}`);
  fs.mkdirSync(directory, { recursive: true });
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const sourceRoot = path.resolve(args["source-root"]);
  const revision = args.revision;
  const registryRevision = Number(revision);
  const revisionDirectory = path.resolve("revisions", revision);
  ensureEmptyRevisionDirectory(revisionDirectory);

  const presets = importPresets(path.join(sourceRoot, MODEL_SOURCE));
  const profiles = importProfiles(path.join(sourceRoot, PROFILE_SOURCE));
  const catalogProviders = new Set(presets.map(preset => preset.provider));
  const dynamicProviders = [...new Set(profiles.flatMap(profile => Object.values(profile.roleBindings))
    .flatMap(binding => Array.isArray(binding) ? binding : [binding])
    .map(selector => selector.replace(/:(minimal|low|medium|high|xhigh|max)$/, ""))
    .filter(selector => selector.includes("/"))
    .map(selector => selector.slice(0, selector.indexOf("/")))
    .filter(provider => !catalogProviders.has(provider)))]
    .sort();
  for (const provider of dynamicProviders) {
    if (!profiles.some(profile => profile.requiredProviders.includes(provider))) {
      fail(`Dynamic provider ${provider} is not declared by any profile`);
    }
  }
  const presetsDocument = { schemaVersion: CONTRACT_VERSION, revision, presets };
  const profilesDocument = { schemaVersion: CONTRACT_VERSION, revision, dynamicProviders, profiles };
  const presetPath = `revisions/${revision}/presets.json`;
  const profilePath = `revisions/${revision}/profiles.json`;
  canonicalWrite(path.resolve(presetPath), presetsDocument);
  canonicalWrite(path.resolve(profilePath), profilesDocument);

  const compatibility = { consumerContract: { minVersion: CONTRACT_VERSION, maxVersion: CONTRACT_VERSION } };
  const provenance = {
    sourceRepository: SOURCE_REPOSITORY,
    sourceRevision: args["source-revision"],
    sourcePaths: [MODEL_SOURCE, PROFILE_SOURCE],
    generatedBy: GENERATOR,
    generatedAt: args["source-date"]
  };
  const snapshot = {
    schemaVersion: CONTRACT_VERSION,
    registryRevision,
    revision,
    compatibility,
    provenance,
    contents: {
      presets: descriptor(presetPath, presetsDocument, presets.length),
      profiles: descriptor(profilePath, profilesDocument, profiles.length)
    }
  };
  const snapshotPath = `revisions/${revision}/snapshot.json`;
  canonicalWrite(path.resolve(snapshotPath), snapshot);
  const signed = {
    registryRevision,
    revision,
    publishedAt: args["source-date"],
    compatibility,
    snapshot: descriptor(snapshotPath, snapshot, 1),
    contents: snapshot.contents,
    provenance
  };
  const manifest = {
    schemaVersion: CONTRACT_VERSION,
    signed,
    signature: { algorithm: "Ed25519", keyId: args["key-id"], value: "" }
  };
  canonicalWrite(path.join(revisionDirectory, "manifest.json"), manifest);
  process.stdout.write(`Imported ${presets.length} presets and ${profiles.length} profiles into revision ${revision}.\n`);
}

main();

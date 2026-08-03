import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const excluded = new Set([".git", "node_modules", "target"]);

function markdownFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (excluded.has(entry.name)) return [];
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) return markdownFiles(path);
    return extname(entry.name) === ".md" ? [path] : [];
  });
}

function githubSlug(value) {
  return value
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/[`*_~]/g, "")
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .trim()
    .replace(/\s+/g, "-");
}

function anchors(path) {
  const counts = new Map();
  const result = new Set();
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const heading = line.match(/^#{1,6}\s+(.+?)\s*#*$/)?.[1];
    if (!heading) continue;
    const base = githubSlug(heading);
    const count = counts.get(base) ?? 0;
    result.add(count === 0 ? base : `${base}-${count}`);
    counts.set(base, count + 1);
  }
  return result;
}

const failures = [];
const anchorCache = new Map();
let checked = 0;

for (const source of markdownFiles(root)) {
  const text = readFileSync(source, "utf8");
  const links = text.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g);
  for (const match of links) {
    let destination = match[1].trim().replace(/^<|>$/g, "");
    if (/^(?:https?:|mailto:|urn:)/i.test(destination)) continue;
    destination = destination.split(/\s+['"]/)[0];

    const [rawPath, rawFragment] = destination.split("#", 2);
    if (!rawPath && !rawFragment) continue;

    const target = rawPath
      ? resolve(dirname(source), decodeURIComponent(rawPath))
      : source;
    checked += 1;

    if (!existsSync(target) || !statSync(target).isFile()) {
      failures.push(`${source.slice(root.length + 1)} -> ${destination} (missing file)`);
      continue;
    }

    if (rawFragment) {
      const expected = decodeURIComponent(rawFragment).toLowerCase();
      const known = anchorCache.get(target) ?? anchors(target);
      anchorCache.set(target, known);
      if (!known.has(expected)) {
        failures.push(`${source.slice(root.length + 1)} -> ${destination} (missing anchor)`);
      }
    }
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}

console.log(`Checked ${checked} internal documentation links.`);


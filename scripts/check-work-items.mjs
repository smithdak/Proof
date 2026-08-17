import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const itemsDirectory = resolve(root, "docs/work/items");
const mapPath = resolve(root, "docs/work/map.md");
const evidenceDirectory = resolve(root, "docs/work/evidence");

const requiredFields = [
  "id",
  "title",
  "status",
  "wave",
  "kind",
  "blocked_by",
  "claimed_by",
  "claimed_at",
  "base_sha",
  "review_gate",
  "accepted_by",
  "accepted_at",
];
const statuses = new Set([
  "proposed",
  "ready",
  "claimed",
  "blocked",
  "review",
  "done",
  "superseded",
]);
const waves = new Set(["now", "next"]);
const kinds = new Set(["decision", "implementation", "qualification"]);
const allowedTransitions = new Map([
  ["proposed", new Set(["ready", "superseded"])],
  ["ready", new Set(["claimed", "superseded"])],
  ["claimed", new Set(["review", "blocked", "superseded"])],
  ["blocked", new Set(["proposed", "ready", "superseded"])],
  ["review", new Set(["done", "claimed", "superseded"])],
  ["done", new Set()],
  ["superseded", new Set()],
]);
const failures = [];

function fail(message) {
  failures.push(message);
}

function parseValue(value) {
  if (value === "null") return null;
  if (value === "[]") return [];
  if (value.startsWith("[") && value.endsWith("]")) {
    return value
      .slice(1, -1)
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean);
  }
  return value;
}

function parseItem(text, label) {
  const lines = text.replaceAll("\r\n", "\n").split("\n");
  if (lines[0] !== "---") {
    fail(`${label}: missing opening frontmatter delimiter`);
    return null;
  }
  const end = lines.indexOf("---", 1);
  if (end === -1) {
    fail(`${label}: missing closing frontmatter delimiter`);
    return null;
  }

  const metadata = {};
  for (const line of lines.slice(1, end)) {
    const match = line.match(/^([a-z_]+):\s*(.*)$/);
    if (!match) {
      fail(`${label}: malformed frontmatter line ${JSON.stringify(line)}`);
      continue;
    }
    const [, key, rawValue] = match;
    if (Object.hasOwn(metadata, key)) fail(`${label}: duplicate field ${key}`);
    metadata[key] = parseValue(rawValue.trim());
  }
  for (const field of requiredFields) {
    if (!Object.hasOwn(metadata, field)) fail(`${label}: missing field ${field}`);
  }
  return { metadata, body: lines.slice(end + 1).join("\n") };
}

function isTimestamp(value) {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) &&
    !Number.isNaN(Date.parse(value))
  );
}

function isSha(value) {
  return typeof value === "string" && /^[0-9a-f]{40}$/.test(value);
}

function gitText(reference, path) {
  const repositoryPath = root.replaceAll("\\", "/");
  const commonArguments = ["-c", `safe.directory=${repositoryPath}`];
  const object = `${reference}:${path.replaceAll("\\", "/")}`;
  const exists = spawnSync("git", [...commonArguments, "cat-file", "-e", object], {
    cwd: root,
    encoding: "utf8",
  });
  if (exists.status !== 0) return null;
  const result = spawnSync("git", [...commonArguments, "show", object], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    fail(`cannot read ${object}: ${result.stderr.trim()}`);
    return null;
  }
  return result.stdout;
}

if (!existsSync(itemsDirectory) || !existsSync(mapPath)) {
  console.error("docs/work/items and docs/work/map.md must exist");
  process.exit(1);
}

const itemFiles = readdirSync(itemsDirectory)
  .filter((name) => /^P-\d{4}-.+\.md$/.test(name))
  .sort();
const items = new Map();
for (const file of itemFiles) {
  const path = resolve(itemsDirectory, file);
  const parsed = parseItem(readFileSync(path, "utf8"), file);
  if (!parsed) continue;
  const metadata = parsed.metadata;
  const expectedPrefix = `${metadata.id}-`;
  if (typeof metadata.id !== "string" || !/^P-\d{4}$/.test(metadata.id)) {
    fail(`${file}: invalid id ${JSON.stringify(metadata.id)}`);
  } else if (!file.startsWith(expectedPrefix)) {
    fail(`${file}: filename does not begin with ${expectedPrefix}`);
  }
  if (items.has(metadata.id)) fail(`${file}: duplicate id ${metadata.id}`);
  items.set(metadata.id, { file, path, ...parsed });
}

for (const [id, item] of items) {
  const metadata = item.metadata;
  if (!statuses.has(metadata.status)) fail(`${id}: invalid status ${metadata.status}`);
  if (!waves.has(metadata.wave)) fail(`${id}: invalid wave ${metadata.wave}`);
  if (!kinds.has(metadata.kind)) fail(`${id}: invalid kind ${metadata.kind}`);
  if (!Array.isArray(metadata.blocked_by)) fail(`${id}: blocked_by must be an array`);
  if (typeof metadata.title !== "string" || metadata.title.length === 0) {
    fail(`${id}: title must be non-empty`);
  }
  if (
    typeof metadata.review_gate !== "string" ||
    !/^(?:none|[a-z0-9][a-z0-9-]*)$/.test(metadata.review_gate)
  ) {
    fail(`${id}: invalid review_gate ${JSON.stringify(metadata.review_gate)}`);
  }
  if (metadata.kind === "decision" && metadata.review_gate !== "project-owner") {
    fail(`${id}: decision items require the project-owner review gate`);
  }
  if (
    /project owner explicitly accepts/i.test(item.body) &&
    metadata.review_gate !== "project-owner"
  ) {
    fail(`${id}: explicit project-owner acceptance requires a matching review gate`);
  }

  for (const dependency of metadata.blocked_by ?? []) {
    if (!items.has(dependency)) fail(`${id}: unknown dependency ${dependency}`);
    if (dependency === id) fail(`${id}: cannot depend on itself`);
  }

  const unclaimed = ["blocked", "proposed", "ready"].includes(metadata.status);
  const hasClaim = [metadata.claimed_by, metadata.claimed_at, metadata.base_sha].every(
    (value) => value !== null,
  );
  if (unclaimed && hasClaim) fail(`${id}: ${metadata.status} item cannot retain a claim`);
  if (unclaimed && [metadata.claimed_by, metadata.claimed_at, metadata.base_sha].some(
    (value) => value !== null,
  )) {
    fail(`${id}: claim metadata must be entirely null while ${metadata.status}`);
  }
  if (["claimed", "review", "done"].includes(metadata.status) && !hasClaim) {
    fail(`${id}: ${metadata.status} item requires complete claim metadata`);
  }
  if (metadata.claimed_at !== null && !isTimestamp(metadata.claimed_at)) {
    fail(`${id}: claimed_at must be an RFC 3339 UTC timestamp`);
  }
  if (metadata.base_sha !== null && !isSha(metadata.base_sha)) {
    fail(`${id}: base_sha must be a lowercase 40-character Git SHA`);
  }

  const hasAcceptance = metadata.accepted_by !== null || metadata.accepted_at !== null;
  if (metadata.status !== "done" && hasAcceptance) {
    fail(`${id}: acceptance metadata is only valid for done items`);
  }
  if (metadata.accepted_at !== null && !isTimestamp(metadata.accepted_at)) {
    fail(`${id}: accepted_at must be an RFC 3339 UTC timestamp`);
  }
  if (
    metadata.status === "done" &&
    metadata.review_gate !== "none" &&
    (metadata.accepted_by === null || metadata.accepted_at === null)
  ) {
    fail(`${id}: done item requires acceptance from ${metadata.review_gate}`);
  }

  const resolvedDependencies = (metadata.blocked_by ?? []).filter(
    (dependency) => items.get(dependency)?.metadata.status === "done",
  );
  if (metadata.status === "blocked" && resolvedDependencies.length === metadata.blocked_by.length) {
    fail(`${id}: blocked item has no unresolved dependency`);
  }
  if (["proposed", "ready", "claimed", "review", "done"].includes(metadata.status)) {
    if (resolvedDependencies.length !== metadata.blocked_by.length) {
      fail(`${id}: ${metadata.status} item still has an unresolved dependency`);
    }
  }

  if (["review", "done"].includes(metadata.status)) {
    const directory = resolve(evidenceDirectory, id);
    const receipt = resolve(directory, "receipt.md");
    const manifest = resolve(directory, "manifest.json");
    if (!existsSync(receipt)) {
      fail(`${id}: ${metadata.status} item lacks receipt.md`);
    } else if (readFileSync(receipt, "utf8").trim().length === 0) {
      fail(`${id}: receipt.md must not be empty`);
    }
    if (!existsSync(manifest)) {
      fail(`${id}: ${metadata.status} item lacks manifest.json`);
    } else {
      try {
        const value = JSON.parse(readFileSync(manifest, "utf8"));
        if (value.item_id !== id) fail(`${id}: manifest item_id does not match`);
        for (const field of [
          "schema_version",
          "base_sha",
          "item_work_commit",
          "commands",
          "environment",
          "artifact_digests",
          "evidence_paths",
        ]) {
          if (!Object.hasOwn(value, field)) fail(`${id}: manifest lacks ${field}`);
        }
        if (!isSha(value.base_sha)) fail(`${id}: manifest base_sha is invalid`);
        if (value.item_work_commit !== "pending-completion-record" && !isSha(value.item_work_commit)) {
          fail(`${id}: manifest item_work_commit is invalid`);
        }
        if (metadata.status === "done" && value.item_work_commit === "pending-completion-record") {
          fail(`${id}: done manifest must bind the completed item-work commit`);
        }
        if (!Array.isArray(value.commands) || value.commands.length === 0) {
          fail(`${id}: manifest commands must be a non-empty array`);
        } else if (
          value.commands.some(
            (entry) =>
              typeof entry?.command !== "string" || !Number.isInteger(entry?.exit_code),
          )
        ) {
          fail(`${id}: every manifest command requires command and integer exit_code`);
        }
        if (!Array.isArray(value.artifact_digests) || value.artifact_digests.length === 0) {
          fail(`${id}: manifest artifact_digests must be a non-empty array`);
        }
        if (!Array.isArray(value.evidence_paths) || value.evidence_paths.length === 0) {
          fail(`${id}: manifest evidence_paths must be a non-empty array`);
        }
      } catch (error) {
        fail(`${id}: manifest.json is invalid JSON: ${error.message}`);
      }
    }
  }
  if (metadata.status === "done" && /Not started|Blocked by/.test(item.body)) {
    fail(`${id}: done item still has an incomplete completion record`);
  }
}

const visiting = new Set();
const visited = new Set();
function visit(id, trail) {
  if (visiting.has(id)) {
    fail(`dependency cycle: ${[...trail, id].join(" -> ")}`);
    return;
  }
  if (visited.has(id)) return;
  visiting.add(id);
  for (const dependency of items.get(id)?.metadata.blocked_by ?? []) {
    if (items.has(dependency)) visit(dependency, [...trail, id]);
  }
  visiting.delete(id);
  visited.add(id);
}
for (const id of items.keys()) visit(id, []);

const mapRows = new Map();
for (const line of readFileSync(mapPath, "utf8").split(/\r?\n/)) {
  if (!line.startsWith("| [")) continue;
  const cells = line.split("|").slice(1, -1).map((cell) => cell.trim());
  if (cells.length !== 4) continue;
  const link = cells[0].match(/^\[([^\]]+)\]\(items\/(P-\d{4}-.+\.md)\)$/);
  if (!link) continue;
  const [, title, file] = link;
  const id = file.match(/^(P-\d{4})-/)?.[1];
  if (mapRows.has(id)) fail(`${id}: duplicate work-map row`);
  const blockers = cells[2] === "none" ? [] : cells[2].split(",").map((entry) => entry.trim());
  mapRows.set(id, {
    title,
    file,
    status: cells[1].replaceAll("`", ""),
    blockers,
  });
}
for (const [id, item] of items) {
  const row = mapRows.get(id);
  if (!row) {
    fail(`${id}: missing work-map row`);
    continue;
  }
  if (row.file !== item.file) fail(`${id}: map points to ${row.file}, expected ${item.file}`);
  if (row.title !== item.metadata.title) fail(`${id}: map title differs from frontmatter`);
  if (row.status !== item.metadata.status) fail(`${id}: map status differs from frontmatter`);
  if (JSON.stringify(row.blockers) !== JSON.stringify(item.metadata.blocked_by)) {
    fail(`${id}: map blockers differ from frontmatter`);
  }
}
for (const id of mapRows.keys()) {
  if (!items.has(id)) fail(`${id}: work-map row has no item file`);
}

const previousReference =
  process.env.PROOF_WORK_ITEMS_BASE ??
  (process.env.GITHUB_ACTIONS === "true" ? "HEAD^" : "HEAD");
for (const [id, item] of items) {
  const path = relative(root, item.path);
  const previousText = gitText(previousReference, path);
  if (previousText === null) continue;
  const previous = parseItem(previousText, `${previousReference}:${path}`);
  if (!previous || previous.metadata.status === item.metadata.status) continue;
  const allowed = allowedTransitions.get(previous.metadata.status);
  if (!allowed?.has(item.metadata.status)) {
    fail(`${id}: invalid transition ${previous.metadata.status} -> ${item.metadata.status}`);
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}

console.log(
  `Checked ${items.size} work items: metadata, lifecycle, dependencies, map parity, transitions, and evidence contracts pass.`,
);

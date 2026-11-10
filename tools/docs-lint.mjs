#!/usr/bin/env node
// Copyright 2026 Bad Monkey. Licensed under the Apache License, Version 2.0.
//
// The docs lint: one script, identical in every public repository's tools/ folder, that holds a README to the
// shape of docs/README-SHAPE.md and a docs/ folder to its index. Node 18 or newer, no dependency.
//
//   node tools/docs-lint.mjs [repo]            lint the README and docs/ of a repository (default: the current one)
//   node tools/docs-lint.mjs --fix [repo]      also write the generated table of contents of each long document
//   node tools/docs-lint.mjs --links <dir>...  check every relative link in every Markdown and HTML file below the dirs
//   node tools/docs-lint.mjs --links --md <dir>...  the same, over the Markdown files alone
//
// Prints one line per problem as file:line: message, and exits 1 when it printed any.

import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";

const README_LINES = 150;
const README_WORDS = 1200;
const SECTION_LINES = 30;
const WHAT_IT_IS_LINES = 5;
const FIRST_SCREEN = 40;
const TOC_AFTER = 200;
const AUDIENCE = /^(?:Written for: |written_for: )\S/;
// A document another program writes says so in its first lines; it keeps the structure its generator gives it.
const GENERATED = /\b(?:[Gg]enerated (?:from|by)|GENERATED)\b/;
const SECTIONS = [
  { name: "Quick start", test: (h) => h.startsWith("Quick start") },
  { name: "What it is", test: (h) => h === "What it is" },
  { name: "Add it to your build", test: (h) => h === "Add it to your build" },
  { name: "Where to read next", test: (h) => h === "Where to read next" },
  { name: "License", test: (h) => h === "License" || h === "Licence" },
];
const SKIP_DIRS = new Set([".git", "node_modules", "target", "build", "dist", ".venv", "venv", "vendor", "__pycache__",
  "javadocs", "javadocs-springai", ".cpcache", "classes", "out", ".gradle", ".idea"]);

const problems = [];
const problem = (file, line, message) => problems.push(`${file}:${line}: ${message}`);

/** The lines of a Markdown text with fenced code marked, so headings and links inside code are never read. */
function scan(text) {
  const lines = text.split("\n");
  let fence = null;
  return lines.map((line) => {
    const open = /^\s*(```+|~~~+)/.exec(line);
    if (fence) {
      if (open && open[1][0] === fence[0] && open[1].length >= fence.length) fence = null;
      return { line, code: true };
    }
    if (open) {
      fence = open[1];
      return { line, code: true };
    }
    return { line, code: false };
  });
}

/** GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens, repeats numbered. */
function slugs(text) {
  const seen = new Map();
  const out = new Set();
  for (const { line, code } of scan(text)) {
    if (code) continue;
    const h = /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);
    if (h) {
      const base = h[1].replace(/<[^>]+>/g, "").replace(/`/g, "").toLowerCase().trim()
        .replace(/[^\p{L}\p{N}\s_-]/gu, "").replace(/\s/g, "-");
      const n = seen.get(base) ?? 0;
      seen.set(base, n + 1);
      out.add(n === 0 ? base : `${base}-${n}`);
    }
    for (const m of line.matchAll(/<a\s+(?:id|name)="([^"]+)"/g)) out.add(m[1]);
  }
  return out;
}

const slugCache = new Map();
function anchorsOf(file) {
  if (!slugCache.has(file)) {
    const text = readFileSync(file, "utf8");
    slugCache.set(file, file.endsWith(".md") ? slugs(text)
      : new Set([...text.matchAll(/\s(?:id|name)="([^"]+)"/g)].map((m) => m[1])));
  }
  return slugCache.get(file);
}

/** The relative links of a Markdown file, with their line numbers; code spans and fences are skipped. */
function markdownLinks(text) {
  const links = [];
  const rows = scan(text);
  rows.forEach(({ line, code }, i) => {
    if (code) return;
    const prose = line.replace(/`[^`]*`/g, "");
    for (const m of prose.matchAll(/\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g)) links.push({ target: m[1], line: i + 1 });
    // a reference definition starts a block: it never continues a paragraph
    const opensBlock = i === 0 || !/\S/.test(rows[i - 1].line) || /^\s*\[[^\]]+\]:\s/.test(rows[i - 1].line);
    if (opensBlock) for (const m of prose.matchAll(/^\s{0,3}\[[^\]]+\]:\s+(\S+)/g)) links.push({ target: m[1], line: i + 1 });
    for (const m of prose.matchAll(/\s(?:href|src)="([^"]+)"/g)) links.push({ target: m[1], line: i + 1 });
  });
  return links;
}

function htmlLinks(text) {
  const links = [];
  text.split("\n").forEach((line, i) => {
    for (const m of line.matchAll(/\s(?:href|src)="([^"]+)"/g)) links.push({ target: m[1], line: i + 1 });
  });
  return links;
}

/** Checks one link from a file: a relative path must exist, and its fragment must name a heading or an id there. */
function checkLink(file, { target, line }, root) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith("//") || target.startsWith("{") || target.includes("${")) return;
  const [rawPath, fragment] = target.split("#");
  let path;
  try {
    path = decodeURIComponent(rawPath.split("?")[0]);
  } catch {
    path = rawPath;
  }
  const dest = path === "" ? file : resolve(dirname(file), path);
  const shown = relative(root, file);
  if (!existsSync(dest)) {
    problem(shown, line, `broken link ${target}: no ${relative(root, dest) || dest}`);
    return;
  }
  if (fragment && statSync(dest).isFile() && /\.(md|html?)$/.test(dest) && !anchorsOf(dest).has(fragment)
      && !anchorsOf(dest).has(decodeURIComponent(fragment))) {
    problem(shown, line, `broken anchor ${target}: ${relative(root, dest) || basename(dest)} has no #${fragment}`);
  }
}

function walk(dir, out = [], kinds = /\.(md|html?)$/) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name) || name.startsWith(".")) continue;
    const p = join(dir, name);
    const s = statSync(p);
    if (s.isDirectory()) walk(p, out, kinds);
    else if (kinds.test(name)) out.push(p);
  }
  return out;
}

/** The generated table of contents of a document: its second- and third-level headings, as GitHub links them. */
function toc(text) {
  const seen = new Map();
  const items = [];
  for (const { line, code } of scan(text)) {
    if (code) continue;
    const h = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line);
    if (!h) continue;
    const base = h[2].replace(/<[^>]+>/g, "").replace(/`/g, "").toLowerCase().trim()
      .replace(/[^\p{L}\p{N}\s_-]/gu, "").replace(/\s/g, "-");
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    if (h[1].length === 2 || h[1].length === 3) {
      items.push(`${h[1].length === 3 ? "  " : ""}- [${h[2].replace(/`/g, "")}](#${n === 0 ? base : `${base}-${n}`})`);
    }
  }
  return items.join("\n");
}

const TOC_OPEN = "<!-- toc: generated by tools/docs-lint.mjs --fix; do not edit -->";
const TOC_CLOSE = "<!-- /toc -->";

function lintDocument(file, root, fix) {
  let text = readFileSync(file, "utf8");
  const shown = relative(root, file);
  const head = text.split("\n").slice(0, 6);
  if (!head.some((l) => AUDIENCE.test(l))) problem(shown, 1, "no audience line: a document opens with \"Written for: ...\" in its first lines");
  const lines = text.split("\n").length;
  if (lines > TOC_AFTER && !head.some((l) => GENERATED.test(l))) {
    const start = text.indexOf(TOC_OPEN);
    const end = text.indexOf(TOC_CLOSE);
    const body = start >= 0 && end > start ? text.slice(0, start) + text.slice(end + TOC_CLOSE.length) : text;
    const want = `${TOC_OPEN}\n${toc(body)}\n${TOC_CLOSE}`;
    const have = start >= 0 && end > start ? text.slice(start, end + TOC_CLOSE.length) : null;
    if (have !== want) {
      if (fix) {
        if (have) text = text.replace(have, want);
        else {
          const at = text.split("\n");
          const audience = at.findIndex((l) => AUDIENCE.test(l));
          at.splice(audience + 1, 0, "", want);
          text = at.join("\n");
        }
        writeFileSync(file, text);
      } else {
        problem(shown, 1, `${lines} lines and ${have ? "a stale" : "no"} generated table of contents: run node tools/docs-lint.mjs --fix`);
      }
    }
  }
  for (const link of markdownLinks(text)) checkLink(file, link, root);
}

function lintReadme(repo, fix) {
  const file = join(repo, "README.md");
  const shown = "README.md";
  if (!existsSync(file)) {
    problem(shown, 1, "no README.md");
    return;
  }
  const text = readFileSync(file, "utf8");
  const rows = scan(text);
  if (rows.length > README_LINES) problem(shown, rows.length, `${rows.length} lines, over the budget of ${README_LINES}`);
  const words = rows.filter((r) => !r.code).map((r) => r.line).join(" ").split(/\s+/).filter((w) => /[\p{L}\p{N}]/u.test(w)).length;
  if (words > README_WORDS) problem(shown, 1, `${words} words of prose, over the budget of ${README_WORDS}`);
  if (!/^# \S/.test(rows[0]?.line ?? "")) problem(shown, 1, "the README opens with its title as a first-level heading");
  const headings = [];
  rows.forEach((r, i) => {
    if (!r.code && /^## /.test(r.line)) headings.push({ title: r.line.slice(3).trim(), line: i + 1 });
    if (!r.code && /^# /.test(r.line) && i > 0) problem(shown, i + 1, "only the title is a first-level heading");
  });
  const firstHeading = headings[0]?.line ?? rows.length;
  if (!rows.slice(1, firstHeading - 1).some((r) => !r.code && /\S/.test(r.line))) {
    problem(shown, 2, "a paragraph under the title says what it is and for whom");
  }
  let next = 0;
  for (const h of headings) {
    const at = SECTIONS.findIndex((s) => s.test(h.title));
    if (at < 0) problem(shown, h.line, `section "${h.title}" is not one of the shape's sections; move it to docs/`);
    else if (at < next) problem(shown, h.line, `section "${h.title}" is out of order: ${SECTIONS.map((s) => s.name).join(", ")}`);
    else if (at > next) problem(shown, h.line, `missing section${at - next > 1 ? "s" : ""} before "${h.title}": ${SECTIONS.slice(next, at).map((s) => s.name).join(", ")}`);
    if (at >= 0) next = Math.max(next, at + 1);
  }
  if (next < SECTIONS.length) problem(shown, rows.length, `missing sections at the end: ${SECTIONS.slice(next).map((s) => s.name).join(", ")}`);
  const quick = headings.find((h) => SECTIONS[0].test(h.title));
  if (quick && quick.line > FIRST_SCREEN) problem(shown, quick.line, `the quick start begins on line ${quick.line}, past the first screen (${FIRST_SCREEN})`);
  headings.forEach((h, i) => {
    const end = (headings[i + 1]?.line ?? rows.length + 1) - 1;
    const length = end - h.line;
    if (!SECTIONS[0].test(h.title) && length > SECTION_LINES) problem(shown, h.line, `section "${h.title}" runs ${length} lines, over ${SECTION_LINES}`);
    if (h.title === "What it is") {
      const body = rows.slice(h.line, end).filter((r) => /\S/.test(r.line)).length;
      if (body > WHAT_IT_IS_LINES) problem(shown, h.line, `"What it is" holds ${body} lines, over ${WHAT_IT_IS_LINES}`);
    }
  });
  for (const link of markdownLinks(text)) checkLink(file, link, repo);
  void fix;
}

function lintDocsFolder(repo, fix) {
  const docs = join(repo, "docs");
  if (!existsSync(docs)) {
    problem("docs/", 1, "no docs/ folder: the README's long content lives there, with docs/README.md as its index");
    return;
  }
  const indexes = [];
  (function folders(dir) {
    indexes.push(dir);
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory() && !name.startsWith(".")) folders(p);
    }
  })(docs);
  for (const dir of indexes) {
    const index = join(dir, "README.md");
    const shownIndex = relative(repo, index);
    if (!existsSync(index)) {
      problem(shownIndex, 1, "no index: every folder of docs/ has a README.md that names each file in it");
      continue;
    }
    const indexText = readFileSync(index, "utf8");
    const named = new Set(markdownLinks(indexText).map((l) => resolve(dir, decodeURIComponent(l.target.split("#")[0]))));
    // a file the index names in a code span, such as a data file beside a generated page, is named too
    for (const m of indexText.matchAll(/`([^`\s]+)`/g)) named.add(resolve(dir, m[1]));
    for (const name of readdirSync(dir)) {
      if (name === "README.md" || name.startsWith(".")) continue;
      const p = join(dir, name);
      const target = statSync(p).isDirectory() ? join(p, "README.md") : p;
      if (!named.has(p) && !named.has(target) && !named.has(p + sep)) problem(shownIndex, 1, `the index does not name ${name}`);
    }
  }
  for (const file of walk(docs)) if (file.endsWith(".md")) lintDocument(file, repo, fix);
}

function lintLinks(dirs, markdownOnly) {
  for (const dir of dirs) {
    const root = resolve(dir);
    const one = statSync(root).isFile();
    for (const file of one ? [root] : walk(root, [], markdownOnly ? /\.md$/ : /\.(md|html?)$/)) {
      const text = readFileSync(file, "utf8");
      for (const link of file.endsWith(".md") ? markdownLinks(text) : htmlLinks(text)) checkLink(file, link, one ? dirname(root) : root);
    }
  }
}

const args = process.argv.slice(2);
if (args[0] === "--links") {
  const markdownOnly = args.includes("--md");
  const dirs = args.slice(1).filter((a) => a !== "--md");
  lintLinks(dirs.length ? dirs : ["."], markdownOnly);
} else {
  const fix = args.includes("--fix");
  const repo = resolve(args.filter((a) => a !== "--fix")[0] ?? ".");
  lintReadme(repo, fix);
  lintDocsFolder(repo, fix);
}
for (const p of problems) console.log(p);
if (problems.length) {
  console.log(`docs-lint: ${problems.length} problem${problems.length === 1 ? "" : "s"}`);
  process.exit(1);
}

import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";

const roots = process.argv.slice(2).map((value) => resolve(value));
if (roots.length === 0) {
  process.stderr.write("usage: write-checksums.mjs PATH...\n");
  process.exit(2);
}

const files = [];
const collect = (path) => {
  const stat = statSync(path);
  if (stat.isDirectory()) {
    for (const entry of readdirSync(path)) collect(join(path, entry));
  } else if (!path.endsWith(".sha256")) {
    files.push(path);
  }
};

for (const root of roots) collect(root);
for (const file of files) {
  const digest = createHash("sha256").update(readFileSync(file)).digest("hex");
  writeFileSync(`${file}.sha256`, `${digest}  ${basename(file)}\n`, "ascii");
}

process.stdout.write(`${files.length} checksum file(s) written\n`);

import { chmodSync, copyFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "../..");
const uiRoot = resolve(scriptDir, "..");

const args = process.argv.slice(2);
const valueAfter = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};

const rustc = spawnSync("rustc", ["-vV"], { encoding: "utf8" });
if (rustc.status !== 0) {
  process.stderr.write(rustc.stderr || "rustc -vV failed\n");
  process.exit(rustc.status ?? 1);
}

const host = rustc.stdout.match(/^host:\s+(.+)$/m)?.[1];
const target = valueAfter("--target") || host;
const profile = valueAfter("--profile") || "debug";
const skipBuild = args.includes("--skip-build");

if (!target || !["debug", "release"].includes(profile)) {
  process.stderr.write("usage: prepare-sidecar.mjs [--target TRIPLE] [--profile debug|release] [--skip-build]\n");
  process.exit(2);
}

const executable = target.includes("windows") ? "sql-connector.exe" : "sql-connector";
const destinationName = target.includes("windows")
  ? `sql-connector-${target}.exe`
  : `sql-connector-${target}`;

if (!skipBuild) {
  const buildArgs = ["build", "--locked", "--target", target, "-p", "sql-connector"];
  if (profile === "release") buildArgs.splice(1, 0, "--release");

  const env = { ...process.env };
  if (target === "x86_64-pc-windows-msvc") {
    env.RUSTFLAGS = [env.RUSTFLAGS, "-C target-feature=+crt-static"].filter(Boolean).join(" ");
  }

  const build = spawnSync("cargo", buildArgs, {
    cwd: repoRoot,
    env,
    stdio: "inherit",
  });
  if (build.status !== 0) process.exit(build.status ?? 1);
}

const source = join(repoRoot, "target", target, profile, executable);
const destinationDir = join(uiRoot, "src-tauri", "binaries");
const destination = join(destinationDir, destinationName);
mkdirSync(destinationDir, { recursive: true });
copyFileSync(source, destination);
if (!target.includes("windows")) chmodSync(destination, 0o755);
process.stdout.write(`${destination}\n`);

import fs from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const dist = path.join(root, "dist");

await fs.rm(dist, { recursive: true, force: true });
await fs.mkdir(dist, { recursive: true });
await fs.copyFile(path.join(root, "index.html"), path.join(dist, "index.html"));
await fs.cp(path.join(root, "src"), path.join(dist, "src"), { recursive: true });
await fs.cp(path.join(root, "public"), dist, { recursive: true });
console.log("Static frontend emitted to dist/.");

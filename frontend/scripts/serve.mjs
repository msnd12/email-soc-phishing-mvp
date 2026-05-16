import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const port = Number(process.env.PORT ?? 5173);
const types = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"]
]);

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${port}`);
  const pathname = url.pathname === "/" ? "/index.html" : url.pathname;
  const target = path.normalize(path.join(root, pathname));
  if (!target.startsWith(root)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  try {
    const resolved = await resolveFile(target, pathname);
    const body = await fs.readFile(resolved);
    res.writeHead(200, { "content-type": types.get(path.extname(resolved)) ?? "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end("Not found");
  }
});

server.listen(port, () => {
  console.log(`Email SOC frontend listening on http://localhost:${port}`);
});

async function resolveFile(target, pathname) {
  try {
    await fs.access(target);
    return target;
  } catch {
    const publicTarget = path.normalize(path.join(root, "public", pathname));
    if (!publicTarget.startsWith(path.join(root, "public"))) {
      throw new Error("Invalid public path");
    }
    await fs.access(publicTarget);
    return publicTarget;
  }
}

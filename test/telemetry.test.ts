import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import * as t from "../src/index.ts";

const SRC = pathToFileURL(join(import.meta.dir, "..", "src", "index.ts")).href;
const TOKEN = "tmk_test";

class Ingest {
  logs: Record<string, any>[] = [];
  metrics: string[] = [];
  status = 200;
  port = 0;
  private server: ReturnType<typeof Bun.serve> | null = null;

  start(): void {
    this.server = Bun.serve({
      port: this.port,
      fetch: async (req) => {
        if (req.headers.get("authorization") !== `Bearer ${TOKEN}`) return new Response("no", { status: 401 });
        let body = Buffer.from(await req.arrayBuffer());
        if (this.status !== 200) return new Response("x", { status: this.status });
        if (req.headers.get("content-encoding") === "gzip") body = gunzipSync(body);
        const path = new URL(req.url).pathname;
        if (path === "/logs") {
          for (const l of body.toString().split("\n")) if (l.trim()) this.logs.push(JSON.parse(l));
        } else this.metrics.push(body.toString());
        return new Response(null, { status: 204 });
      },
    });
    this.port = this.server.port!;
  }

  stop(): void {
    this.server?.stop(true);
    this.server = null;
  }

  get url(): string {
    return `http://127.0.0.1:${this.port}`;
  }
}

async function waitFor(cond: () => boolean, ms = 8000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error("timeout waiting for condition");
    await Bun.sleep(25);
  }
}

const fast = { flushMs: 40, metricsMs: 60_000, drainMs: 40, backoffMinMs: 40, backoffMaxMs: 120, captureConsole: false };

let ing: Ingest;
let dir: string;
const spoolFiles = (sub = "spool") => (existsSync(join(dir, sub)) ? readdirSync(join(dir, sub)).filter((f) => !f.endsWith(".tmp")) : []);

function childScript(body: string): string {
  const p = join(dir, `child-${Math.random().toString(36).slice(2)}.ts`);
  writeFileSync(p, `import * as t from ${JSON.stringify(SRC)};\n${body}\n`);
  return p;
}

function spawn(script: string, extra: Record<string, string> = {}) {
  return Bun.spawn([process.execPath, script], {
    env: {
      ...process.env,
      TELEMETRY_URL: ing.url,
      TELEMETRY_TOKEN: TOKEN,
      TELEMETRY_SPOOL_DIR: dir,
      TELEMETRY_SERVER: "child",
      ...extra,
    },
    stdout: "ignore",
    stderr: "ignore",
  });
}

beforeEach(() => {
  ing = new Ingest();
  ing.start();
  dir = mkdtempSync(join(tmpdir(), "telem-"));
});

afterEach(async () => {
  await t.shutdown();
  ing.stop();
  rmSync(dir, { recursive: true, force: true });
});

describe("delivery", () => {
  test("a: server up, every record arrives with the standard fields", async () => {
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, server: "web1", ...fast });
    for (let i = 0; i < 5; i++) t.info(`line ${i}`, { n: i });
    await t.flush();
    expect(ing.logs.map((l) => l.n)).toEqual([0, 1, 2, 3, 4]);
    const l = ing.logs[0];
    expect(l.level).toBe("info");
    expect(l.server).toBe("web1");
    expect(l._msg).toBe("line 0");
    expect(Date.parse(l._time)).toBeGreaterThan(0);
    expect(spoolFiles()).toEqual([]);
  });

  test("b: server down spools, server back delivers once, in order, spool empty", async () => {
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, ...fast });
    ing.stop();
    let n = 0;
    for (let round = 0; round < 3; round++) {
      for (let i = 0; i < 4; i++) t.info("m", { n: n++ });
      await t.flush();
    }
    expect(spoolFiles().length).toBeGreaterThanOrEqual(3);
    expect(ing.logs.length).toBe(0);
    ing.start();
    await waitFor(() => ing.logs.length === 12);
    await waitFor(() => spoolFiles().length === 0);
    expect(ing.logs.map((l) => l.n)).toEqual([...Array(12).keys()]);
  });

  test("b2: a 500 spools and a 400 goes to dead/", async () => {
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, ...fast });
    ing.status = 500;
    t.info("kept");
    await t.flush();
    expect(spoolFiles().length).toBeGreaterThan(0);
    ing.status = 200;
    await waitFor(() => ing.logs.some((l) => l._msg === "kept"));
    await t.shutdown();
    t.init({ url: ing.url, token: "wrong", spoolDir: dir, ...fast });
    t.info("rejected");
    await t.flush();
    expect(spoolFiles("dead").length).toBeGreaterThan(0);
    expect(spoolFiles()).toEqual([]);
  });

  test("e: spool cap drops oldest metrics first, then logs", async () => {
    const blob = () => Buffer.from(crypto.getRandomValues(new Uint8Array(12_000))).toString("base64");
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, spoolMaxMb: 100, ...fast, drainMs: 60_000 });
    ing.stop();
    for (let i = 0; i < 4; i++) {
      t.info("big", { blob: blob() });
      await t.flush();
    }
    await t.shutdown();
    const size = (kind: string) =>
      spoolFiles()
        .filter((f) => f.startsWith(kind))
        .reduce((s, f) => s + statSync(join(dir, "spool", f)).size, 0);
    const metricsBytes = size("metrics");
    const logsBytes = size("logs");
    const metricFiles = spoolFiles().filter((f) => f.startsWith("metrics")).length;
    expect(metricFiles).toBeGreaterThanOrEqual(4);

    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, spoolMaxMb: (metricsBytes + logsBytes - metricsBytes / 2) / 1048576, ...fast, drainMs: 60_000 });
    await t.shutdown();
    const left = spoolFiles();
    expect(left.filter((f) => f.startsWith("logs")).length).toBe(4);
    expect(left.filter((f) => f.startsWith("metrics")).length).toBeLessThan(metricFiles);

    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, spoolMaxMb: logsBytes / 2 / 1048576, ...fast, drainMs: 60_000 });
    await t.shutdown();
    const after = spoolFiles();
    expect(after.filter((f) => f.startsWith("metrics")).length).toBeLessThanOrEqual(1);
    expect(after.filter((f) => f.startsWith("logs")).length).toBeLessThan(4);
  });
});

describe("crashes", () => {
  test("c: uncaught exception and unhandled rejection reach the server on the next run", async () => {
    ing.stop();
    for (const body of ["throw new Error('boom-uncaught');", "Promise.reject(new Error('boom-rejection'));"]) {
      const script = childScript(`t.init({ flushMs: 60000, metricsMs: 60000, drainMs: 60000 });\nt.info('before crash');\n${body}\nsetInterval(() => {}, 1000);`);
      const p = spawn(script);
      expect(await p.exited).toBe(1);
    }
    expect(spoolFiles().length).toBeGreaterThanOrEqual(2);
    expect(readdirSync(dir).filter((f) => f.startsWith("run."))).toEqual([]);
    ing.start();
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, ...fast });
    await t.flush();
    await waitFor(() => spoolFiles().length === 0);
    const fatals = ing.logs.filter((l) => l.level === "fatal");
    expect(fatals.map((l) => l._msg).sort()).toEqual(["Error: boom-rejection", "Error: boom-uncaught"]);
    expect(fatals[0].stack).toContain("boom");
    expect(fatals[0].fingerprint).toHaveLength(12);
    expect(ing.logs.filter((l) => l._msg === "before crash").length).toBe(2);
    expect(ing.logs.some((l) => l._msg.includes("ended uncleanly"))).toBe(false);
  });

  test("d: kill -9 is reported as an unclean exit by the next start", async () => {
    const script = childScript(`t.init({ flushMs: 30, metricsMs: 60000, drainMs: 60000 });\nsetInterval(() => {}, 1000);`);
    const p = spawn(script);
    await waitFor(() => readdirSync(dir).some((f) => f.startsWith("run.")));
    p.kill(9);
    await p.exited;
    await Bun.sleep(400);
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, markerStaleMs: 300, ...fast });
    await t.flush();
    const hit = ing.logs.find((l) => l._msg.includes("previous process ended uncleanly"));
    expect(hit?.level).toBe("fatal");
    expect(readdirSync(dir).filter((f) => /^run\.\d+\.[0-9a-f]+$/.test(f)).length).toBe(1);
  });

  test("a live process sharing the volume is not reported", async () => {
    const script = childScript(`t.init({ flushMs: 30, metricsMs: 60000, drainMs: 60000 });\nawait Bun.sleep(1500);\nawait t.shutdown();`);
    const p = spawn(script);
    await waitFor(() => readdirSync(dir).some((f) => f.startsWith("run.")));
    await Bun.sleep(300);
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, markerStaleMs: 300, ...fast });
    await t.flush();
    await Bun.sleep(300);
    await t.flush();
    expect(ing.logs.some((l) => l._msg.includes("ended uncleanly"))).toBe(false);
    await p.exited;
  });

  test("f: two processes on one spool dir never send a record twice", async () => {
    const writer = (tag: string) =>
      childScript(`t.init({ flushMs: 30, metricsMs: 60000, drainMs: 30, backoffMinMs: 30, backoffMaxMs: 60 });\nfor (let i = 0; i < 25; i++) t.info('rec', { id: '${tag}-' + i });\nawait t.flush();\nawait t.shutdown();`);
    const drainer = childScript(`t.init({ flushMs: 30, metricsMs: 60000, drainMs: 30, backoffMinMs: 30, backoffMaxMs: 60 });\nawait t.flush();\nawait Bun.sleep(300);\nawait t.shutdown();`);

    for (const tag of ["a", "b"]) await spawn(writer(tag)).exited;
    expect(ing.logs.filter((l) => l._msg === "rec").length).toBe(50);

    ing.stop();
    for (const tag of ["c", "d"]) await spawn(writer(tag)).exited;
    expect(spoolFiles().length).toBeGreaterThanOrEqual(2);
    ing.start();
    await Promise.all([spawn(drainer).exited, spawn(drainer).exited]);
    await waitFor(() => spoolFiles().length === 0);

    const ids = ing.logs.filter((l) => l._msg === "rec").map((l) => l.id);
    expect(ids.length).toBe(100);
    expect(new Set(ids).size).toBe(100);
  });
});

describe("behaviour", () => {
  test("disabled without url or token: no files, no-op API", async () => {
    const root = join(dir, "never");
    t.init({ url: "", token: TOKEN, spoolDir: root });
    t.info("x");
    t.counter("c").inc();
    t.gauge("g").set(1);
    t.histogram("h").observe(1);
    expect(await t.time(async () => 7, t.histogram("h"))).toBe(7);
    await t.flush();
    expect(existsSync(root)).toBe(false);
  });

  test("secrets are scrubbed", async () => {
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, ...fast });
    t.info("auth Bearer abc.def-123 and tmk_SECRETvalue ok", { password: "p", nested: { api_key: "k", fine: 1 }, note: "Bearer zzz" });
    await t.flush();
    const l = ing.logs[0];
    expect(l._msg).toBe("auth Bearer [redacted] and tmk_[redacted] ok");
    expect(l.password).toBe("[redacted]");
    expect(l.nested).toEqual({ api_key: "[redacted]", fine: 1 });
    expect(l.note).toBe("Bearer [redacted]");
  });

  test("repeated warnings inside the window collapse into one line with a count", async () => {
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, ...fast });
    for (let i = 0; i < 6; i++) t.warn("same problem");
    t.warn("other problem");
    await t.flush();
    const same = ing.logs.filter((l) => l._msg === "same problem");
    expect(same.length).toBe(1);
    expect(same[0].count).toBe(6);
    expect(ing.logs.filter((l) => l._msg === "other problem")[0].count).toBeUndefined();
  });

  test("metrics render with ms timestamps, buckets, built-ins and a server label", async () => {
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, server: "web1", ...fast });
    t.counter("jobs_total", { queue: "mail" }).inc(3);
    t.gauge("depth").set(9);
    const h = t.histogram("req_seconds", { route: '/a"b' }, [0.1, 1]);
    h.observe(0.05);
    h.observe(0.5);
    await t.flush();
    const text = ing.metrics.join("\n");
    const ts = /jobs_total\{queue="mail",server="web1"\} 3 (\d{13})/.exec(text);
    expect(ts).not.toBeNull();
    expect(text).toContain('depth{server="web1"} 9 ');
    expect(text).toContain('req_seconds_bucket{route="/a\\"b",le="0.1",server="web1"} 1 ');
    expect(text).toContain('req_seconds_bucket{route="/a\\"b",le="1",server="web1"} 2 ');
    expect(text).toContain('req_seconds_bucket{route="/a\\"b",le="+Inf",server="web1"} 2 ');
    expect(text).toContain('req_seconds_count{route="/a\\"b",server="web1"} 2 ');
    for (const m of ["process_resident_memory_bytes", "process_up", "telemetry_spool_bytes", "telemetry_dropped_total", "telemetry_send_failures_total"]) {
      expect(text).toContain(`# TYPE ${m} `);
    }
  });

  test("a metric is capped at 1000 series and invalid names are ignored", async () => {
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, ...fast });
    for (let i = 0; i < 1010; i++) t.counter("many_total", { id: i }).inc();
    t.counter("bad name").inc();
    t.counter("ok_total", { "bad-label": 1 }).inc();
    await t.flush();
    const text = ing.metrics.join("\n");
    expect(text.split("\n").filter((l) => l.startsWith("many_total{")).length).toBe(1000);
    expect(text).toContain('telemetry_dropped_total{reason="series"');
    expect(text).not.toContain("bad name");
    expect(ing.logs.some((l) => l.level === "warn" && l._msg.includes("series cap"))).toBe(true);
  });

  test("console capture ships lines, still prints, and is undone by shutdown", async () => {
    const before = console.warn;
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, ...fast, captureConsole: true });
    expect(console.warn).not.toBe(before);
    console.log("hello %s", "world");
    console.error("bad thing");
    await t.flush();
    expect(ing.logs.some((l) => l._msg === "hello world" && l.level === "info")).toBe(true);
    expect(ing.logs.some((l) => l._msg === "bad thing" && l.level === "error")).toBe(true);
    await t.shutdown();
    expect(console.warn).toBe(before);
  });

  test("time() records seconds even when the function throws", async () => {
    t.init({ url: ing.url, token: TOKEN, spoolDir: dir, ...fast });
    const h = t.histogram("op_seconds");
    await expect(t.time(async () => { throw new Error("x"); }, h)).rejects.toThrow("x");
    await t.flush();
    expect(ing.metrics.join("\n")).toMatch(/op_seconds_count\{server="[^"]*"\} 1 /);
  });

  test("an unwritable spool dir falls back to the temp dir", () => {
    const file = join(dir, "afile");
    writeFileSync(file, "x");
    mkdirSync(join(dir, "ok"));
    t.init({ url: ing.url, token: TOKEN, spoolDir: join(file, "sub"), ...fast });
    t.info("x");
    expect(existsSync(join(tmpdir(), "telemetry", "spool"))).toBe(true);
  });
});

import { createHash, randomBytes } from "node:crypto";
import {
  accessSync,
  closeSync,
  constants,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { format } from "node:util";
import { gzipSync } from "node:zlib";

export type Labels = Record<string, string | number | boolean>;
export type Fields = Record<string, unknown>;

export interface InitOptions {
  app?: string;
  url?: string;
  token?: string;
  spoolDir?: string;
  spoolMaxMb?: number;
  server?: string;
  captureConsole?: boolean;
  captureExceptions?: boolean;
  flushMs?: number;
  metricsMs?: number;
  drainMs?: number;
  backoffMinMs?: number;
  backoffMaxMs?: number;
  dedupeMs?: number;
  markerStaleMs?: number;
  postTimeoutMs?: number;
}

export interface CounterHandle {
  inc(n?: number): void;
}
export interface GaugeHandle {
  set(v: number): void;
}
export interface HistogramHandle {
  observe(v: number): void;
}

type Kind = "logs" | "metrics";
type Result = "ok" | "retry" | "dead";
type Rec = Record<string, unknown>;
type Series = { labels: string; v: number; sum: number; n: number; b?: number[] };
type Metric = { kind: "counter" | "gauge" | "histogram"; buckets?: number[]; series: Map<string, Series>; warned: boolean };
type Run = { force: boolean; metrics: boolean; timeout: number; deadline: number; down: boolean };

const DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
const MAX_SERIES = 1000;
const MAX_BATCH_BYTES = 8 * 1024 * 1024;
const MAX_BUFFER_LINES = 1000;
const STALE_CLAIM_MS = 5 * 60_000;
const SECRET_KEY = /password|passwd|secret|token|authorization|api[_-]?key|cookie/i;
const METRIC_RE = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const LABEL_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const SPOOL_RE = /^(logs|metrics)-(\d+)-(\d+)-(\d+)\.ndjson\.gz$/;
const MARKER_RE = /^run\.(\d+)\.([0-9a-f]+)$/;

const lastDiag = new Map<string, number>();
function diag(key: string, msg: string): void {
  const now = Date.now();
  if (now - (lastDiag.get(key) ?? 0) < 60_000) return;
  lastDiag.set(key, now);
  try {
    process.stderr.write(`[telemetry] ${msg}\n`);
  } catch {}
}

function scrubStr(s: string): string {
  return s.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]").replace(/tmk_[A-Za-z0-9_-]+/g, "tmk_[redacted]");
}

function scrub(v: unknown, depth = 0): unknown {
  if (typeof v === "string") return scrubStr(v);
  if (v instanceof Error) return { name: v.name, message: scrubStr(v.message), stack: scrubStr(v.stack ?? "") };
  if (!v || typeof v !== "object") return v;
  if (depth > 4) return "[truncated]";
  if (Array.isArray(v)) return v.map((x) => scrub(x, depth + 1));
  const out: Rec = {};
  for (const [k, x] of Object.entries(v)) out[k] = SECRET_KEY.test(k) ? "[redacted]" : scrub(x, depth + 1);
  return out;
}

function ser(o: Rec): string {
  try {
    return JSON.stringify(o, (_, v) => (typeof v === "bigint" ? String(v) : v));
  } catch {
    return JSON.stringify({ _time: o._time, level: o.level, server: o.server, _msg: String(o._msg) });
  }
}

function sha(s: string): string {
  return createHash("sha1").update(s).digest("hex").slice(0, 12);
}

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(typeof e === "string" ? e : ser({ _msg: e }));
}

function errorFingerprint(e: Error): string {
  const frames = (e.stack ?? "")
    .split("\n")
    .filter((l) => /^\s+at /.test(l))
    .slice(0, 3)
    .map((l) => l.replace(/:\d+:\d+\)?$/, ""));
  return sha(e.name + "\n" + frames.join("\n"));
}

function escLabel(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

function chunkLines(lines: string[]): string[] {
  const out: string[] = [];
  let cur: string[] = [];
  let bytes = 0;
  for (const l of lines) {
    const n = Buffer.byteLength(l) + 1;
    if (cur.length && bytes + n > MAX_BATCH_BYTES) {
      out.push(cur.join("\n") + "\n");
      cur = [];
      bytes = 0;
    }
    cur.push(l);
    bytes += n;
  }
  if (cur.length) out.push(cur.join("\n") + "\n");
  return out;
}

function numEnv(v: string | undefined): number | undefined {
  const n = Number(v);
  return v && Number.isFinite(n) && n > 0 ? n : undefined;
}

type Config = Required<Omit<InitOptions, "app" | "url" | "token" | "spoolDir">> & {
  app: string;
  url: string;
  token: string;
  root: string;
};

function resolveConfig(o: InitOptions): Config | null {
  const env = process.env;
  const url = (o.url ?? env.TELEMETRY_URL ?? "").replace(/\/+$/, "");
  const token = o.token ?? env.TELEMETRY_TOKEN ?? "";
  if (!url || !token) return null;
  const wanted = o.spoolDir ?? env.TELEMETRY_SPOOL_DIR ?? (process.platform === "win32" ? join(tmpdir(), "telemetry") : "/var/lib/telemetry");
  let root: string | null = null;
  for (const dir of [wanted, join(tmpdir(), "telemetry")]) {
    try {
      mkdirSync(join(dir, "spool"), { recursive: true });
      accessSync(dir, constants.W_OK);
      root = dir;
      break;
    } catch {}
    diag("spooldir", `spool dir ${dir} is not writable, trying the temp dir`);
  }
  if (!root) {
    diag("nospool", "no writable spool dir, telemetry disabled");
    return null;
  }
  return {
    app: o.app ?? "",
    url,
    token,
    root,
    spoolMaxMb: o.spoolMaxMb ?? numEnv(env.TELEMETRY_SPOOL_MAX_MB) ?? 500,
    server: o.server ?? env.TELEMETRY_SERVER ?? hostname(),
    captureConsole: o.captureConsole ?? true,
    captureExceptions: o.captureExceptions ?? true,
    flushMs: o.flushMs ?? 2000,
    metricsMs: o.metricsMs ?? 30_000,
    drainMs: o.drainMs ?? 1000,
    backoffMinMs: o.backoffMinMs ?? 1000,
    backoffMaxMs: o.backoffMaxMs ?? 300_000,
    dedupeMs: o.dedupeMs ?? 5000,
    markerStaleMs: o.markerStaleMs ?? 120_000,
    postTimeoutMs: o.postTimeoutMs ?? 10_000,
  };
}

const NOOP = { inc() {}, set() {}, observe() {} };
const CONSOLE_LEVEL = { log: "info", info: "info", warn: "warn", error: "error", debug: "debug" } as const;

class Client {
  private buf: string[] = [];
  private pending = new Map<string, { rec: Rec; at: number; count: number }>();
  private metrics = new Map<string, Metric>();
  private inflight = new Set<{ kind: Kind; gz: Buffer }>();
  private dropped = { spool_logs: 0, spool_metrics: 0, series: 0 };
  private failures = 0;
  private chain: Promise<unknown> = Promise.resolve();
  private seq = 0;
  private spoolNonEmpty = false;
  private lastScan = 0;
  private nextDrainAt = 0;
  private backoff: number;
  private ticking = false;
  private exiting = false;
  private stopped = false;
  private timers: ReturnType<typeof setInterval>[] = [];
  private restore: (() => void)[] = [];
  private inCapture = false;
  private readonly runId = randomBytes(3).toString("hex");
  private readonly started = new Date().toISOString();
  private readonly spoolDir: string;
  private readonly deadDir: string;
  private readonly marker: string;

  constructor(private cfg: Config) {
    this.spoolDir = join(cfg.root, "spool");
    this.deadDir = join(cfg.root, "dead");
    this.marker = join(cfg.root, `run.${process.pid}.${this.runId}`);
    this.backoff = cfg.backoffMinMs;
  }

  start(): void {
    const c = this.cfg;
    this.spoolNonEmpty = this.list().length > 0;
    this.enforceCap(true);
    this.touchMarker();
    this.scanMarkers();
    const every = (ms: number, fn: () => void) => {
      const t = setInterval(fn, ms);
      t.unref?.();
      this.timers.push(t);
    };
    every(c.flushMs, () => this.tick());
    every(c.metricsMs, () => {
      this.scanMarkers();
      void this.enqueue(() => this.deliver("metrics", this.render(), this.run({})));
    });
    every(c.drainMs, () => {
      if (!this.spoolNonEmpty && Date.now() - this.lastScan < 30_000) return;
      void this.enqueue(() => this.drain(this.run({})));
    });
    this.hook();
  }

  private hook(): void {
    const on = (ev: string, fn: (...a: any[]) => void) => {
      process.on(ev, fn);
      this.restore.push(() => process.removeListener(ev, fn));
    };
    on("exit", () => {
      this.syncSpoolAll();
      this.dropMarker();
    });
    on("beforeExit", () => {
      if (this.exiting) return;
      this.exiting = true;
      void this.enqueue(() => this.flushInner(this.run({ force: true, metrics: true, final: true })));
    });
    for (const sig of ["SIGTERM", "SIGINT"] as const) {
      const h = () => {
        void this.enqueue(() => this.flushInner(this.run({ force: true, metrics: true, final: true }))).finally(() => {
          this.dropMarker();
          if (process.listenerCount(sig) <= 1) {
            process.removeListener(sig, h);
            process.kill(process.pid, sig);
          }
        });
      };
      on(sig, h);
    }
    if (this.cfg.captureExceptions) {
      on("uncaughtExceptionMonitor", (err: unknown, origin: string) => {
        this.add(this.fatal(err, origin), false);
        this.syncSpoolAll();
        this.dropMarker();
      });
      const rej = (reason: unknown) => {
        this.add(this.fatal(reason, "unhandledRejection"), false);
        if (process.listenerCount("unhandledRejection") <= 1) {
          this.syncSpoolAll();
          this.dropMarker();
          process.stderr.write(`Unhandled rejection: ${toError(reason).stack}\n`);
          process.exit(1);
        }
      };
      on("unhandledRejection", rej);
    }
    if (this.cfg.captureConsole) {
      for (const m of ["log", "info", "warn", "error", "debug"] as const) {
        const orig = console[m];
        const wrapper = (...a: unknown[]) => {
          orig.apply(console, a);
          if (this.inCapture) return;
          this.inCapture = true;
          try {
            this.log(CONSOLE_LEVEL[m], format(...a));
          } finally {
            this.inCapture = false;
          }
        };
        console[m] = wrapper;
        this.restore.push(() => {
          if (console[m] === wrapper) console[m] = orig;
        });
      }
    }
  }

  private fatal(err: unknown, origin: string): Rec {
    const e = toError(err);
    return this.record("fatal", `${e.name}: ${e.message}`, {
      fingerprint: errorFingerprint(e),
      stack: e.stack,
      error_type: e.name,
      origin,
    });
  }

  private record(level: string, msg: string, fields?: Fields): Rec {
    const f = (fields ? scrub(fields) : {}) as Rec;
    return { ...f, _time: new Date().toISOString(), level, server: this.cfg.server, _msg: scrubStr(msg) };
  }

  log(level: string, msg: string | Error, fields?: Fields): void {
    if (this.stopped) return;
    let m: string;
    let f = fields;
    if (msg instanceof Error) {
      m = `${msg.name}: ${msg.message}`;
      f = { fingerprint: errorFingerprint(msg), stack: msg.stack, error_type: msg.name, ...fields };
    } else m = String(msg);
    const rec = this.record(level, m, f);
    const dedupe = level === "warn" || level === "error";
    if (dedupe && rec.fingerprint === undefined) rec.fingerprint = sha(level + "\n" + rec._msg);
    this.add(rec, dedupe);
  }

  private add(rec: Rec, dedupe: boolean): void {
    if (dedupe) {
      const key = String(rec.fingerprint);
      const hit = this.pending.get(key);
      if (hit) hit.count++;
      else this.pending.set(key, { rec, at: Date.now(), count: 1 });
      return;
    }
    this.buf.push(ser(rec));
    if (this.buf.length >= MAX_BUFFER_LINES) void this.enqueue(() => this.flushInner(this.run({})));
  }

  private releasePending(all: boolean): void {
    const now = Date.now();
    for (const [k, e] of this.pending) {
      if (!all && now - e.at < this.cfg.dedupeMs) continue;
      this.pending.delete(k);
      if (e.count > 1) e.rec.count = e.count;
      this.buf.push(ser(e.rec));
    }
  }

  private series(name: string, kind: Metric["kind"], labels: Labels, buckets?: number[]): Series | null {
    if (!METRIC_RE.test(name)) {
      diag("metric:" + name, `invalid metric name ${name}`);
      return null;
    }
    const names = Object.keys(labels).sort();
    if (names.some((k) => !LABEL_RE.test(k) || k.startsWith("__"))) {
      diag("label:" + name, `invalid label name on ${name}`);
      return null;
    }
    let m = this.metrics.get(name);
    if (!m) {
      m = {
        kind,
        buckets: kind === "histogram" ? [...(buckets ?? DEFAULT_BUCKETS)].sort((a, b) => a - b) : undefined,
        series: new Map(),
        warned: false,
      };
      this.metrics.set(name, m);
    } else if (m.kind !== kind) {
      diag("kind:" + name, `metric ${name} is already a ${m.kind}`);
      return null;
    }
    const key = names.map((k) => `${k}\u0000${labels[k]}`).join("\u0001");
    let s = m.series.get(key);
    if (s) return s;
    if (m.series.size >= MAX_SERIES) {
      this.dropped.series++;
      if (!m.warned) {
        m.warned = true;
        this.log("warn", `metric ${name} hit the ${MAX_SERIES} series cap, new label sets are dropped`);
      }
      return null;
    }
    s = {
      labels: names.map((k) => `${k}="${escLabel(String(labels[k]))}"`).join(","),
      v: 0,
      sum: 0,
      n: 0,
      b: m.buckets?.map(() => 0),
    };
    m.series.set(key, s);
    return s;
  }

  counter(name: string, labels: Labels = {}): CounterHandle {
    const s = this.series(name, "counter", labels);
    return s ? { inc: (n = 1) => void (s.v += n) } : NOOP;
  }

  gauge(name: string, labels: Labels = {}): GaugeHandle {
    const s = this.series(name, "gauge", labels);
    return s ? { set: (v) => void (s.v = v) } : NOOP;
  }

  histogram(name: string, labels: Labels = {}, buckets?: number[]): HistogramHandle {
    const s = this.series(name, "histogram", labels, buckets);
    const bounds = this.metrics.get(name)?.buckets;
    if (!s || !bounds) return NOOP;
    return {
      observe: (v) => {
        bounds.forEach((le, i) => {
          if (v <= le) s.b![i]++;
        });
        s.sum += v;
        s.n++;
      },
    };
  }

  private spoolBytes(): number {
    let total = 0;
    try {
      for (const f of readdirSync(this.spoolDir)) {
        try {
          total += statSync(join(this.spoolDir, f)).size;
        } catch {}
      }
    } catch {}
    return total;
  }

  render(): string {
    const ts = Date.now();
    const sv = `server="${escLabel(this.cfg.server)}"`;
    const lbl = (user: string, extra = "") => {
      const parts = [user, extra].filter(Boolean);
      if (!/(^|,)server="/.test(user)) parts.push(sv);
      return `{${parts.join(",")}}`;
    };
    const out: string[] = [];
    for (const [name, m] of this.metrics) {
      out.push(`# TYPE ${name} ${m.kind}`);
      for (const s of m.series.values()) {
        if (m.kind !== "histogram") {
          if (Number.isFinite(s.v)) out.push(`${name}${lbl(s.labels)} ${s.v} ${ts}`);
          continue;
        }
        m.buckets!.forEach((le, i) => out.push(`${name}_bucket${lbl(s.labels, `le="${le}"`)} ${s.b![i]} ${ts}`));
        out.push(`${name}_bucket${lbl(s.labels, 'le="+Inf"')} ${s.n} ${ts}`);
        out.push(`${name}_sum${lbl(s.labels)} ${s.sum} ${ts}`);
        out.push(`${name}_count${lbl(s.labels)} ${s.n} ${ts}`);
      }
    }
    out.push("# TYPE process_resident_memory_bytes gauge", `process_resident_memory_bytes{${sv}} ${process.memoryUsage.rss()} ${ts}`);
    out.push("# TYPE process_up gauge", `process_up{${sv}} 1 ${ts}`);
    out.push("# TYPE telemetry_spool_bytes gauge", `telemetry_spool_bytes{${sv}} ${this.spoolBytes()} ${ts}`);
    out.push("# TYPE telemetry_dropped_total counter");
    for (const [reason, n] of Object.entries(this.dropped)) out.push(`telemetry_dropped_total{reason="${reason}",${sv}} ${n} ${ts}`);
    out.push("# TYPE telemetry_send_failures_total counter", `telemetry_send_failures_total{${sv}} ${this.failures} ${ts}`);
    return out.join("\n") + "\n";
  }

  private run(o: { force?: boolean; metrics?: boolean; final?: boolean }): Run {
    const timeout = o.final ? Math.min(3000, this.cfg.postTimeoutMs) : this.cfg.postTimeoutMs;
    return {
      force: !!o.force,
      metrics: !!o.metrics,
      timeout,
      deadline: o.final ? Date.now() + 3000 : Infinity,
      down: false,
    };
  }

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.chain.then(fn, fn);
    this.chain = p.catch(() => {});
    return p;
  }

  private tick(): void {
    if (this.ticking) return;
    this.ticking = true;
    void this.enqueue(() => this.flushInner(this.run({}))).finally(() => (this.ticking = false));
  }

  flush(): Promise<void> {
    return this.enqueue(() => this.flushInner(this.run({ force: true, metrics: true })));
  }

  private async flushInner(r: Run): Promise<void> {
    this.releasePending(r.force);
    this.touchMarker();
    const lines = this.buf;
    this.buf = [];
    for (const chunk of chunkLines(lines)) await this.deliver("logs", chunk, r);
    if (r.metrics) await this.deliver("metrics", this.render(), r);
    if (r.force && this.spoolNonEmpty && !r.down) await this.drain(r);
  }

  private async deliver(kind: Kind, text: string, r: Run): Promise<void> {
    const gz = gzipSync(text);
    if (this.spoolNonEmpty && !r.down) await this.drain(r);
    if (this.spoolNonEmpty || r.down) {
      this.spool(kind, gz);
      return;
    }
    const item = { kind, gz };
    this.inflight.add(item);
    const res = await this.post(kind, gz, r.timeout);
    if (res === "retry") {
      r.down = true;
      this.spool(kind, gz);
    } else if (res === "dead") this.writeFile(this.deadDir, kind, gz);
    this.inflight.delete(item);
  }

  private async post(kind: Kind, gz: Buffer, timeout: number): Promise<Result> {
    try {
      const res = await fetch(`${this.cfg.url}/${kind}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.cfg.token}`,
          "Content-Type": kind === "logs" ? "application/x-ndjson" : "text/plain",
          "Content-Encoding": "gzip",
        },
        body: new Uint8Array(gz),
        signal: AbortSignal.timeout(timeout),
      });
      await res.arrayBuffer().catch(() => {});
      if (res.ok) return "ok";
      this.failures++;
      const s = res.status;
      if (s >= 500 || s === 408 || s === 429) {
        diag("http", `ingest answered ${s}, will retry`);
        return "retry";
      }
      diag("http", `ingest rejected a ${kind} batch with ${s}, moved to dead/`);
      return "dead";
    } catch (e) {
      this.failures++;
      diag("net", `ingest unreachable: ${(e as Error)?.message ?? e}`);
      return "retry";
    }
  }

  private writeFile(dir: string, kind: Kind, gz: Buffer): boolean {
    try {
      mkdirSync(dir, { recursive: true });
      const final = join(dir, `${kind}-${Date.now()}-${process.pid}-${this.seq++}.ndjson.gz`);
      const tmp = final + ".tmp";
      const fd = openSync(tmp, "w");
      try {
        writeSync(fd, gz);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, final);
      return true;
    } catch (e) {
      diag("write", `cannot write spool file: ${(e as Error)?.message ?? e}`);
      this.dropped[kind === "logs" ? "spool_logs" : "spool_metrics"]++;
      return false;
    }
  }

  private spool(kind: Kind, gz: Buffer): void {
    if (this.writeFile(this.spoolDir, kind, gz)) this.spoolNonEmpty = true;
    this.enforceCap(false);
  }

  private syncSpoolAll(): void {
    this.releasePending(true);
    const lines = this.buf;
    this.buf = [];
    for (const chunk of chunkLines(lines)) this.writeFile(this.spoolDir, "logs", gzipSync(chunk));
    for (const it of this.inflight) this.writeFile(this.spoolDir, it.kind, it.gz);
    this.inflight.clear();
  }

  private list(): { name: string; kind: Kind; ms: number; seq: number }[] {
    let names: string[] = [];
    try {
      names = readdirSync(this.spoolDir);
    } catch {}
    const out = [];
    for (const name of names) {
      const m = SPOOL_RE.exec(name);
      if (m) out.push({ name, kind: m[1] as Kind, ms: Number(m[2]), seq: Number(m[4]) });
    }
    return out.sort((a, b) => a.ms - b.ms || a.seq - b.seq);
  }

  private reclaimStale(): void {
    let names: string[] = [];
    try {
      names = readdirSync(this.spoolDir);
    } catch {}
    for (const n of names) {
      const m = /^(.*\.ndjson\.gz)\.sending\.\d+$/.exec(n);
      if (!m) continue;
      try {
        if (Date.now() - statSync(join(this.spoolDir, n)).mtimeMs > STALE_CLAIM_MS) renameSync(join(this.spoolDir, n), join(this.spoolDir, m[1]));
      } catch {}
    }
  }

  private async drain(r: Run): Promise<void> {
    const now = Date.now();
    if (!r.force && now < this.nextDrainAt) return;
    this.lastScan = now;
    this.reclaimStale();
    for (const f of this.list()) {
      if (Date.now() > r.deadline) return;
      const path = join(this.spoolDir, f.name);
      const claim = `${path}.sending.${process.pid}`;
      let gz: Buffer;
      try {
        renameSync(path, claim);
        const t = new Date();
        utimesSync(claim, t, t);
        gz = readFileSync(claim);
      } catch {
        continue;
      }
      const res = await this.post(f.kind, gz, r.timeout);
      if (res === "retry") {
        try {
          renameSync(claim, path);
        } catch {}
        r.down = true;
        this.nextDrainAt = Date.now() + this.backoff;
        this.backoff = Math.min(this.backoff * 2, this.cfg.backoffMaxMs);
        return;
      }
      try {
        if (res === "dead") {
          mkdirSync(this.deadDir, { recursive: true });
          renameSync(claim, join(this.deadDir, f.name));
        } else unlinkSync(claim);
      } catch {}
      this.backoff = this.cfg.backoffMinMs;
      this.nextDrainAt = 0;
    }
    this.spoolNonEmpty = this.list().length > 0;
  }

  private enforceCap(quiet: boolean): void {
    const max = this.cfg.spoolMaxMb * 1024 * 1024;
    let total = 0;
    try {
      for (const n of readdirSync(this.spoolDir)) {
        try {
          total += statSync(join(this.spoolDir, n)).size;
        } catch {}
      }
    } catch {
      return;
    }
    if (total <= max) return;
    const files = this.list();
    const order = [...files.filter((f) => f.kind === "metrics"), ...files.filter((f) => f.kind === "logs")];
    let dropped = 0;
    for (const f of order) {
      if (total <= max) break;
      const p = join(this.spoolDir, f.name);
      try {
        const size = statSync(p).size;
        unlinkSync(p);
        total -= size;
        dropped++;
        this.dropped[f.kind === "logs" ? "spool_logs" : "spool_metrics"]++;
      } catch {}
    }
    if (dropped && !quiet) this.log("warn", `spool is over ${this.cfg.spoolMaxMb} MB, dropped ${dropped} oldest batches`);
  }

  private touchMarker(): void {
    try {
      const t = new Date();
      utimesSync(this.marker, t, t);
    } catch {
      try {
        writeFileSync(this.marker, JSON.stringify({ pid: process.pid, host: hostname(), app: this.cfg.app, started: this.started }));
      } catch {}
    }
  }

  private dropMarker(): void {
    try {
      unlinkSync(this.marker);
    } catch {}
  }

  private scanMarkers(): void {
    let names: string[] = [];
    try {
      names = readdirSync(this.cfg.root);
    } catch {}
    for (const n of names) {
      const m = MARKER_RE.exec(n);
      if (!m || n === `run.${process.pid}.${this.runId}`) continue;
      const p = join(this.cfg.root, n);
      try {
        const st = statSync(p);
        if (Date.now() - st.mtimeMs <= this.cfg.markerStaleMs) continue;
        const claim = `${p}.reaped.${process.pid}`;
        renameSync(p, claim);
        let info: Rec = {};
        try {
          info = JSON.parse(readFileSync(claim, "utf8"));
        } catch {}
        unlinkSync(claim);
        this.add(
          this.record("fatal", "previous process ended uncleanly (killed/OOM?)", {
            fingerprint: "unclean-exit",
            prev_pid: Number(m[1]),
            prev_host: info.host,
            prev_started: info.started,
            prev_last_seen: st.mtime.toISOString(),
          }),
          false,
        );
      } catch {}
    }
  }

  async shutdown(): Promise<void> {
    if (this.stopped) return;
    await this.enqueue(() => this.flushInner(this.run({ force: true, metrics: true, final: true })));
    this.stopped = true;
    this.timers.forEach(clearInterval);
    this.restore.forEach((f) => f());
    this.dropMarker();
  }
}

let client: Client | null = null;

export function init(opts: InitOptions = {}): void {
  if (client) return;
  const cfg = resolveConfig(opts);
  if (!cfg) return;
  client = new Client(cfg);
  client.start();
}

export function log(level: string, msg: string | Error, fields?: Fields): void {
  client?.log(level, msg, fields);
}
export const info = (msg: string | Error, fields?: Fields): void => log("info", msg, fields);
export const warn = (msg: string | Error, fields?: Fields): void => log("warn", msg, fields);
export const error = (msg: string | Error, fields?: Fields): void => log("error", msg, fields);

export function counter(name: string, labels?: Labels): CounterHandle {
  return client?.counter(name, labels) ?? NOOP;
}
export function gauge(name: string, labels?: Labels): GaugeHandle {
  return client?.gauge(name, labels) ?? NOOP;
}
export function histogram(name: string, labels?: Labels, buckets?: number[]): HistogramHandle {
  return client?.histogram(name, labels, buckets) ?? NOOP;
}

export async function time<T>(fn: () => T | Promise<T>, h: HistogramHandle): Promise<T> {
  const start = performance.now();
  try {
    return await fn();
  } finally {
    h.observe((performance.now() - start) / 1000);
  }
}

export function flush(): Promise<void> {
  return client?.flush() ?? Promise.resolve();
}

export async function shutdown(): Promise<void> {
  const c = client;
  client = null;
  await c?.shutdown();
}

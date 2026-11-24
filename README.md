# @righttechsoft/telemetry

Logs, metrics and crash capture for the RightTech telemetry ingest. Bun and Node 18+, no runtime dependencies. Protocol: `docs/telemetry.md` in the taskmaster repo.

## Install

```
bun add github:righttechsoft/telemetry-ts#v0.1.0
```

Bun runs `src/index.ts` directly. Node uses the committed `dist/index.js` (`bun run build` regenerates it).

## Setup

```ts
import * as telemetry from "@righttechsoft/telemetry";

telemetry.init({ app: "myapp" });
```

| Env | Meaning |
|---|---|
| `TELEMETRY_URL` | ingest URL; unset = disabled (no timers, no files) |
| `TELEMETRY_TOKEN` | API token with a telemetry app name; unset = disabled |
| `TELEMETRY_SPOOL_DIR` | default `/var/lib/telemetry` (temp dir if not writable) |
| `TELEMETRY_SPOOL_MAX_MB` | default 500 |
| `TELEMETRY_SERVER` | default hostname |

`init` arguments override env. Options: `captureConsole` and `captureExceptions` (both default on), `flushMs` (2000), `metricsMs` (30000).

Docker: mount a volume at the spool dir, shared by all replicas of the app.

```yaml
volumes:
  - telemetry:/var/lib/telemetry
```

## Logs

```ts
telemetry.info("order placed", { order_id: 42 });
telemetry.warn("card declined");
telemetry.error(new Error("db down"));
telemetry.log("debug", "x");
```

With `captureConsole`, `console.log/info/warn/error/debug` ship too and still print. With `captureExceptions`, an uncaught exception or unhandled rejection becomes a `fatal` line with stack and `fingerprint`; it is written to the spool synchronously before the process dies, and Node's exit behaviour is unchanged. A process killed without a chance to run code (OOM, `kill -9`) is reported by the next process on the same volume as `previous process ended uncleanly`.

Fields named like `password|secret|token|authorization|api_key|cookie` are redacted, as are `Bearer ...` and `tmk_...` in messages. Identical warn/error lines within 5 s become one line with `count`.

## Metrics

```ts
telemetry.counter("jobs_total", { queue: "mail" }).inc();
telemetry.gauge("queue_depth").set(12);
const h = telemetry.histogram("job_seconds", { queue: "mail" });
h.observe(0.4);
await telemetry.time(() => doWork(), h);
```

Snapshots go out every 30 s with a millisecond timestamp per sample, and a `server` label is added. Max 1000 series per metric. Built in: `process_resident_memory_bytes`, `process_up`, `telemetry_spool_bytes`, `telemetry_dropped_total`, `telemetry_send_failures_total`.

HTTP request metrics: record them yourself in your framework's middleware.

```ts
const hist = (route: string, method: string) => telemetry.histogram("http_request_duration_seconds", { route, method });
const start = performance.now();
await next();
hist(matchedRoute, req.method).observe((performance.now() - start) / 1000);
telemetry.counter("http_requests_total", { route: matchedRoute, method: req.method, status: `${Math.floor(res.status / 100)}xx` }).inc();
```

Use the route pattern, never the raw path.

## Delivery

`flush()` sends everything now (logs and a metrics snapshot); `shutdown()` flushes (3 s limit) and stops. SIGTERM/SIGINT/beforeExit do the same, then the process exits as it would have.

At-least-once. A batch that cannot be sent (network error, 5xx, 408, 429) is written to `<spool>/spool/`, retried oldest first with backoff from 1 s to 5 min, and new data queues behind it. A 4xx other than 408/429 goes to `<spool>/dead/`. Several processes may share one spool dir; a duplicate is possible only if a process dies between a send and its delete. Over the size cap the oldest metrics files are dropped first, then the oldest logs, and `telemetry_dropped_total` counts them.

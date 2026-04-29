# Performance Benchmark Report — OpenConext Private-Key Agent

**Date:** 2025-04-29  
**Test duration:** 481 seconds (~8 minutes wall-clock)  
**Environment:** Docker (PHP 8.5-FPM, OpenSSL backend), MacOS developer host (not production hardware)  
**PHP-FPM workers:** default configuration; sign and decrypt phases run sequentially (not interleaved)  
**Debug logging:** enabled (`LOG_LEVEL=debug`); Monolog JSON to stdout  
**Key material:** RSA 2048-bit (dev-signing-key, dev-decryption-key)

> ⚠️ **Important caveat:** This benchmark ran on a MacOS developer machine, not on production
> hardware or a Linux server. Absolute throughput and latency numbers will differ in a production
> environment. Results should be treated as a pre-production baseline, not a production sign-off.

---

## Management Conclusion

The OpenConext Private-Key Agent shows **stable, promising performance** on a single developer
instance, with zero errors across 454,274 requests and no stability events throughout the test.
Validation on production-grade hardware is required before making production capacity decisions.

| Metric | Value |
|--------|-------|
| Total requests served | 454,274 |
| Total errors | **0** |
| Container restarts | **0** |
| OOM kills | **0** |
| Segfaults | **0** |
| Peak single-instance throughput (sign, Phase 2, 20c) | **1,109 req/s** |
| Peak single-instance throughput (decrypt, Phase 3, 50c) | **1,111 req/s** |
| P50 latency under sustained load (20 concurrent) | ~16–19 ms |
| P99 latency under sustained load (20 concurrent) | ~46–54 ms |
| Backend crypto latency (avg) | **1–2 ms** |
| Peak memory usage (observed at 10 s sampling) | 366 MiB |

**Key findings for decision-makers:**

- **Single-instance throughput above 1,000 req/s** was sustained at both 20 and 50 concurrent
  clients. The underlying RSA operation completes in 1–2 ms on average. Whether this scales to
  multiple instances requires dedicated horizontal-scaling tests.
- **Memory footprint is modest** (≤ 366 MiB peak under 50-concurrent stress), well within typical
  container allocation budgets.
- **Post-stress recovery is degraded**: at identical concurrency (6c), throughput after the stress
  burst dropped 23 % for sign and 36 % for decrypt compared to the pre-stress baseline. The cause
  is unconfirmed; PHP-FPM worker configuration is a likely factor and warrants investigation.
- **Long-tail latency spikes occurred under load**: the maximum response time reached 2,683 ms
  under 50-concurrent sign load (Phase 3), with at least two additional spikes exceeding 1 s
  across phases. P99 values remain below 140 ms. The root cause has not been identified.
- **The service is a strong candidate for production deployment**, but production hardware
  benchmarks, PHP-FPM tuning, and SLA definition are recommended before formal sign-off.

---

## 1. Test Configuration

### Load Phases

| Phase | Concurrency | Duration per endpoint | Endpoints |
|-------|------------|----------------------|-----------|
| Phase 1 — Baseline | 6 | 30 s | sign, decrypt |
| Phase 2 — Sustained | 20 | 120 s | sign, decrypt |
| Phase 3 — Stress burst | 50 | 60 s | sign, decrypt |
| Phase 4 — Recovery | 6 | 30 s | sign, decrypt |

### Endpoints under test

| Endpoint | Key | Algorithm |
|----------|-----|-----------|
| `POST /sign/dev-signing-key` | dev-signing-key (RSA 2048) | `rsa-pkcs1-v1_5-sha256` |
| `POST /decrypt/dev-decryption-key` | dev-decryption-key (RSA 2048) | `rsa-pkcs1-oaep-mgf1-sha256` |

### Instrumentation

- **Debug-level timing logs** emitted by `SignController` and `DecryptController` via Monolog JSON;
  each request logs `durationMs` of the backend RSA operation (excludes HTTP/FPM overhead).
- **Docker stats** sampled every 10 seconds (43 samples total).
- **Load generator:** `hey` (HTTP load testing tool).

---

## 2. Per-Phase Throughput and Latency

### Phase 1 — Baseline (6 concurrent, 30 s)

| Endpoint | Req/s | Avg | p50 | p95 | p99 | Slowest | HTTP 200 | Errors |
|----------|-------|-----|-----|-----|-----|---------|----------|--------|
| sign/dev-signing-key | 775.2 | 7.7 ms | 7.5 ms | 11.0 ms | 13.3 ms | 39.5 ms | 23,261 | 0 |
| decrypt/dev-decryption-key | 747.7 | 8.0 ms | 7.7 ms | 11.5 ms | 14.2 ms | 37.4 ms | 22,438 | 0 |

Observations:
- Consistent, low-latency responses at light concurrency.
- Decrypt is marginally slower than sign, consistent with OAEP padding overhead.

### Phase 2 — Sustained Load (20 concurrent, 120 s)

| Endpoint | Req/s | Avg | p50 | p95 | p99 | Slowest | HTTP 200 | Errors |
|----------|-------|-----|-----|-----|-----|---------|----------|--------|
| sign/dev-signing-key | 1,108.9 | 18.0 ms | 16.4 ms | 30.1 ms | 46.0 ms | 1,124.7 ms | 133,081 | 0 |
| decrypt/dev-decryption-key | 959.3 | 20.8 ms | 19.1 ms | 35.8 ms | 54.0 ms | 136.5 ms | 115,137 | 0 |

Observations:
- **Peak sustained throughput for sign: 1,109 req/s** — a 43 % increase over baseline.
- Latency growth is linear with concurrency, as expected for a CPU-bound workload.
- The 1,124.7 ms slowest request for sign is an extreme tail event; its cause is unidentified
  (P99 = 46 ms, so this affected well under 1 % of requests).

### Phase 3 — Stress Burst (50 concurrent, 60 s)

| Endpoint | Req/s | Avg | p50 | p95 | p99 | Slowest | HTTP 200 | Errors |
|----------|-------|-----|-----|-----|-----|---------|----------|--------|
| sign/dev-signing-key | 1,021.6 | 48.9 ms | 40.9 ms | 97.7 ms | 136.2 ms | 2,682.8 ms | 61,353 | 0 |
| decrypt/dev-decryption-key | 1,111.1 | 45.0 ms | 39.6 ms | 88.0 ms | 125.7 ms | 377.9 ms | 66,707 | 0 |

Observations:
- Throughput remains above 1,000 req/s at 50 concurrent clients — the service does not degrade
  catastrophically under burst load.
- **Throughput begins to plateau / slightly decline compared to Phase 2** (sign: 1,022 vs 1,109
  req/s; decrypt remains comparable at 1,111 vs 959 req/s); average latency triples (18 ms → 49 ms)
  indicating the service is approaching its single-instance saturation point.
- Multiple extreme tail events are observed: 2,682.8 ms for sign and 377.9 ms for decrypt.
  Root causes are unidentified from this benchmark alone.
- **Zero HTTP errors across all 128,060 stress-phase requests.**

### Phase 4 — Recovery Check (6 concurrent, 30 s)

| Endpoint | Req/s | Avg | p50 | p95 | p99 | Slowest | HTTP 200 | Errors |
|----------|-------|-----|-----|-----|-----|---------|----------|--------|
| sign/dev-signing-key | 597.6 | 10.0 ms | 9.7 ms | 14.4 ms | 18.8 ms | 67.6 ms | 17,943 | 0 |
| decrypt/dev-decryption-key | 478.3 | 12.5 ms | 10.7 ms | 21.4 ms | 53.5 ms | 328.0 ms | 14,354 | 0 |

Observations:
- Recovery throughput is **23–36 % below the Phase 1 baseline** at identical concurrency/duration.
  This is a significant regression for decrypt specifically.
- Average latency increased from 7.7 ms (Phase 1) to 10.0 ms (Phase 4) for sign. PHP-FPM worker
  state after heavy load is a plausible hypothesis; profiling would be needed to confirm.
- P99 for decrypt climbed to 53.5 ms (vs 14.2 ms in Phase 1) — persistent elevated tail latency
  following the stress burst.
- No errors; the service remained stable throughout recovery.

---

## 3. Backend Crypto Operation Timing (Debug Logs)

These timings measure only the RSA operation inside the PHP controller, excluding HTTP/FPM
queueing, TLS, network, and request-parsing overhead.

| Operation | n | Min | Avg | p95 | p99 | Max |
|-----------|---|-----|-----|-----|-----|-----|
| `sign` (RSA-PKCS1-v1.5-SHA256) | 235,639 | 1 ms | 1.4 ms | 4 ms | 8 ms | 65 ms |
| `decrypt` (RSA-OAEP-MGF1-SHA256) | 218,636 | 1 ms | 1.6 ms | 5 ms | 9 ms | 81 ms |

Key insight: **The cryptographic backend accounts for only 1–2 ms of each request's total
latency.** Under sustained 20-concurrent load, end-to-end HTTP latency averages 18–21 ms — meaning
16–19 ms is consumed by non-crypto request overhead (PHP-FPM queueing, Symfony framework,
Docker network, and HTTP infrastructure). This ratio confirms that further backend crypto
optimisation would yield minimal gains; PHP-FPM worker tuning would have greater impact at higher
concurrency.

The total debug-logged operations (235,639 + 218,636 = 454,275) agrees within one count of the
total HTTP 200 responses (454,274), confirming no silent failures.

---

## 4. Memory Analysis

Docker stats were sampled every 10 seconds (43 samples) throughout all four phases.

| Metric | Value |
|--------|-------|
| Minimum | 43.9 MiB |
| Average | 106.5 MiB |
| Maximum (observed at 10 s sampling granularity) | 365.8 MiB |
| Container limit | 15,667 MiB (15.6 GiB) |
| Peak utilisation | **≤ 2.3 % of limit** |

Observations:
- Memory grows proportionally with PHP-FPM worker count under stress and is reclaimed after the
  burst phase ends.
- At the observed peak (365.8 MiB), the service uses approximately 2.3 % of the 15.6 GiB
  container memory limit. Short-lived spikes between samples may be higher.
- No OOM kill occurred. For production deployments, a 512 MiB container memory limit provides
  comfortable headroom over the observed maximum.
- CPU usage peaked at ~257 % (2.57 cores on the macOS host) during Phase 1 and averaged ~190 %
  during sustained phases, consistent with a multi-process PHP-FPM setup.

---

## 5. Stability Assessment

| Indicator | Result |
|-----------|--------|
| Container restarts | **0** |
| OOM killed | **false** |
| Last container exit code | **0** |
| Segfaults detected | **0** |
| Backend ERROR/CRITICAL log entries | **0** |
| Total HTTP non-200 responses | **0** |

The service ran without any stability events across all 454,274 requests and ~8 minutes of
continuous load. There were no segfaults, no backend exceptions, and no OOM events.

---

## 6. Observations and Recommendations

### Strengths

1. **Zero-error operation**: 454,274/454,274 requests succeeded. The service is highly reliable
   under all tested concurrency levels.
2. **Low crypto latency**: RSA operations complete in 1–2 ms on average, well within the
   sub-10 ms target for federated identity flows.
3. **Efficient memory use**: Peak memory under 50-concurrent stress is only ~366 MiB, enabling
   dense container packing.
4. **Graceful degradation under stress**: Even at 50 concurrent clients, throughput stays above
   1,000 req/s with p99 below 140 ms.

### Areas for Attention

1. **Post-stress recovery regression**: Phase 4 throughput (479–598 req/s) is 23–36 % below the
   Phase 1 baseline (748–775 req/s) at identical settings, and P99 for decrypt nearly quadrupled.
   PHP-FPM `pm.max_spare_servers` / `pm.process_idle_timeout` tuning is a likely lever; profiling
   is needed to confirm the root cause.

2. **Long-tail latency spikes**: Multiple requests exceeded 1 s across phases (1,124.7 ms in
   Phase 2 sign, 2,682.8 ms in Phase 3 sign). While statistically rare (P99 ≤ 136 ms), the root
   cause is unknown. Consider setting PHP-FPM `request_terminate_timeout` to enforce an upper
   bound.

3. **Non-crypto request overhead dominates latency**: At 20+ concurrent clients, non-crypto
   overhead (16–19 ms of ~18–21 ms total) outweighs the 1–2 ms crypto cost. Increasing
   `pm.max_children` or migrating to a non-blocking runtime (e.g., RoadRunner) would reduce this
   overhead.

4. **Production hardware validation required**: All results were obtained on a MacOS developer
   host. Throughput and latency figures should be re-measured on production-grade Linux hardware
   before capacity planning.

5. **Missing `bench-results.txt` persistence**: The benchmark script writes results to a temp
   directory under `/tmp/`. For CI/CD integration, add an `--output-dir` option to persist results.

### Benchmark Script Fixes Applied

The following discrepancies between the original `tools/comprehensive-perf-test.sh` and the
actual implementation were identified and corrected:

| Issue | Fix Applied |
|-------|-------------|
| Log messages `"sign completed"` / `"decrypt completed"` did not exist | Added `$logger->debug(...)` with `durationMs` to `SignController` and `DecryptController` |
| Script grepped for `"BackendException"` (never logged) | Changed to grep for `level_name: ERROR/CRITICAL` in Monolog JSON output |
| Script extracted `durationMs` field that did not exist | Added `durationMs` to the debug log context |
| `docker logs --since UNIX_TIMESTAMP` silently returns empty output on this Docker version | Changed to relative format `--since Xm` computed from elapsed test time |
| `grep -c` exits 1 on zero matches, killing script under `set -euo pipefail` | Wrapped log analysis block with `set +e` / `set -e` |
| `declare -A` (associative arrays) not supported in bash 3.2 (macOS default) | Rewrote per-phase table rendering in portable awk |
| `restore_log_level()` not called when stats collector was killed early | Added explicit call before `trap - EXIT` |

---

## 7. Raw Data Reference

All raw benchmark data was saved by the test run:

```
/tmp/pka-comprehensive-zXtqkM/
  bench-results.txt       # pipe-delimited per-phase throughput/latency data
  docker-stats.csv        # 10-second memory/CPU samples
  sign-timing.txt         # 235,639 individual sign durationMs values
  decrypt-timing.txt      # 218,636 individual decrypt durationMs values
  container-logs.txt      # filtered container logs for this test run
  mem-parsed.txt          # parsed MiB memory values for statistics
```

---

*Report generated by `tools/comprehensive-perf-test.sh` with debug logging enabled (`LOG_LEVEL=debug`).*

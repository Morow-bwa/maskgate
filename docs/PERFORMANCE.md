# Performance

Privacy stages are measured separately because remote-provider latency would hide local overhead.

```powershell
python -m evaluation.benchmark_privacy --iterations 500
```

The benchmark uses fixed synthetic data and reports mean, p95, and maximum latency for bounded
canonicalization, detection, risk, combined detection/policy/tokenization, final wire guard, and
output guard. Results describe one machine and one short fixture; they are not an SLA.

Strict streaming deliberately buffers supported output fields until complete, so time-to-first-safe
token is approximately provider completion time rather than first upstream token time. OCR/PDF/media
latency depends on file size, page count, resolution, and local optional dependencies and should be
measured with deployment-specific non-sensitive fixtures.

## Bounded local resource sample

`python scripts/measure_resources.py` exercises only the local mock Chat path. On the September 12,
2026 Windows 11 development machine (16 GB RAM), one run used 12 requests at concurrency 4 with a
64 KiB message per request. It completed in 2.858 seconds; process working set rose from 68,784,128
to 81,596,416 bytes, a sampled delta of 12,812,288 bytes. Admission finished with zero active
operations and zero reserved bytes. This is a bounded regression sample, not an RPS target,
multi-worker measurement or proof against OOM under different payloads.

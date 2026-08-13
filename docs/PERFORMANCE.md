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

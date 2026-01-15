# File Transfer Chunk Size Guide

This document explains the chunk size limits and optimal settings for file transfers over different transports.

## Quick Reference

| Transport | Default Chunk | Safe Maximum | Best For | Notes |
|-----------|---------------|--------------|----------|-------|
| **WSMan (HTTP/S)** | 256 KB | 256 KB | Default config | Limited by MaxEnvelopeSizeKb |
| **HvSocket (VMBus)** | 1 MB | 2 MB | PowerShell Direct | No envelope limit |

## WSMan (HTTP/HTTPS) Transport

### Limiting Factor: MaxEnvelopeSizeKb

WinRM uses `MaxEnvelopeSizeKb` to limit SOAP envelope size:

| Setting | Default | Maximum |
|---------|---------|---------|
| MaxEnvelopeSizeKb | 500 KB | 8192 KB (8 MB) |

### Chunk Size Calculation

When transferring files, the data is:

1. **Read from disk** (raw bytes)
2. **Base64 encoded** (+33% size increase)
3. **Wrapped in PowerShell script** (~1 KB overhead)
4. **Wrapped in SOAP envelope** (~2-3 KB overhead)

**Formula:**

```
Safe chunk size = (MaxEnvelopeSizeKb × 1024 - 4096) / 1.33
```

**Examples:**

| MaxEnvelopeSizeKb | Raw Chunk Size | Base64 Size | Fits? |
|-------------------|----------------|-------------|-------|
| 500 KB (default) | 350 KB | ~466 KB | ✅ Yes |
| 500 KB | 400 KB | ~533 KB | ❌ Too large |
| 1024 KB | 750 KB | ~1000 KB | ✅ Yes |
| 8192 KB (max) | 6 MB | ~8 MB | ✅ Yes |

### Configuration (Server-Side)

To increase the limit on the Windows target:

```powershell
# View current setting
Get-Item WSMan:\localhost\MaxEnvelopeSizeKb

# Increase to 8 MB (maximum)
Set-Item WSMan:\localhost\MaxEnvelopeSizeKb -Value 8192

# Restart WinRM service
Restart-Service WinRM
```

Command line alternative:

```cmd
winrm set winrm/config @{MaxEnvelopeSizekb="8192"}
```

### Recommended Settings

| Scenario | MaxEnvelopeSizeKb | Chunk Size |
|----------|-------------------|------------|
| Default (no config change) | 500 KB | 350 KB |
| Performance-tuned server | 2048 KB | 1.5 MB |
| Maximum performance | 8192 KB | 6 MB |

---

## HvSocket (PowerShell Direct) Transport

### No SOAP Envelope Limit

HvSocket bypasses HTTP entirely:

```
WSMan:          HTTP Header + SOAP Envelope + Base64 PSRP
HvSocket:       Length Prefix (4 bytes) + Raw SOAP Envelope
```

No `MaxEnvelopeSizeKb` constraint applies!

### VMBus Ring Buffer Limits

HvSocket uses VMBus channels with ring buffers:

| Setting | Default | Recommended | Maximum |
|---------|---------|-------------|---------|
| Ring Buffer Size | 1 MB | 2 MB | 4 MB |

**Note:** These are per-channel buffers, not per-message limits. Large messages are automatically fragmented across the ring buffer.

### Practical Limits

While there's no protocol limit, practical considerations apply:

| Factor | Recommendation |
|--------|----------------|
| Memory usage | < 16 MB per chunk |
| PowerShell variable size | < 2 GB (practical: < 100 MB) |
| Transfer efficiency | 1-2 MB chunks optimal |

### Recommended Settings

| Scenario | Chunk Size | Rationale |
|----------|------------|-----------|
| Default | 1 MB | Good balance of speed vs. memory |
| High-memory VM | 2 MB | Fewer round trips |
| Low-memory VM | 512 KB | Reduce memory pressure |

---

## Performance Comparison

Estimated transfer times for 100 MB file:

| Transport | Chunk Size | Chunks | Estimated Time | Speed |
|-----------|------------|--------|----------------|-------|
| WSMan (default) | 256 KB | 400 | ~2 min | ~0.9 MB/s |
| WSMan (optimized) | 350 KB | 286 | ~1.5 min | ~1.2 MB/s |
| WSMan (max config) | 1 MB | 100 | ~50 sec | ~2 MB/s |
| HvSocket | 1 MB | 100 | ~10 sec | ~10 MB/s |
| HvSocket | 2 MB | 50 | ~6 sec | ~17 MB/s |

**Note:** Actual performance varies based on network latency, server CPU, and disk speed.

---

## Troubleshooting

### Error: "Request size exceeded MaxEnvelopeSize quota"

**Cause:** Chunk size + Base64 overhead exceeds MaxEnvelopeSizeKb.

**Solution:**

1. Reduce chunk size, OR
2. Increase MaxEnvelopeSizeKb on server:

   ```powershell
   Set-Item WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048
   ```

### Error: "Out of memory" during transfer

**Cause:** Chunk size too large for available memory.

**Solution:** Reduce chunk size:

```bash
-chunk-size 262144   # 256 KB
```

### Slow transfer speeds

**Causes:**

1. Chunk size too small (too many round trips)
2. MaxRunspaces set to 1 (sequential uploads)

**Solution:**

```bash
-chunk-size 1048576 -max-runspaces 4   # 1 MB chunks, 4 parallel
```

---

## CLI Usage Examples

### WSMan (Default Config)

```bash
# Safe for any WinRM server (default config)
./psrp-client -server host -tls -ntlm \
  -copy "/tmp/file.bin=>C:\Temp\file.bin"
```

### WSMan (Performance Tuned)

Requires server config: `Set-Item WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048`

```bash
# Use larger chunks after configuring server
./psrp-client -server host -tls -ntlm \
  -chunk-size 1572864 \
  -copy "/tmp/file.bin=>C:\Temp\file.bin"
```

### HvSocket (PowerShell Direct)

```bash
# HvSocket can use larger chunks
./psrp-client -vm <VMID> \
  -chunk-size 2097152 \
  -copy "/tmp/file.bin=>C:\Temp\file.bin"
```

---

## Implementation Notes

The `go-psrp` client uses these defaults:

| Setting | Default | Configurable Via |
|---------|---------|------------------|
| ChunkSize | 256 KB | `-chunk-size` flag (planned), `WithChunkSize()` option |
| MaxConcurrency | 4 | `-max-runspaces` flag |
| ChunkTimeout | 60 seconds | `WithChunkTimeout()` option |
| VerifyChecksum | false | `-verify` flag |

Future enhancement: Transport-aware automatic chunk sizing.

---

## References

- [WinRM Quotas](https://learn.microsoft.com/en-us/windows/win32/winrm/quotas)
- [MS-PSRP Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/)
- [Hyper-V Socket Documentation](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service)
- [VMBus Architecture](https://www.kernel.org/doc/html/latest/virt/hyperv/vmbus.html)

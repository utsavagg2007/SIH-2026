# NetFlow → Detection integration: verified result — 2026-10-05

Verification of Advitya's `advitiya/netflow-e2e-detection` work (`3c183d2`,
merged to `compiled` as `8309b40`), merged here as `3220bce`.

**Integration and verification only.** No model was re-tuned, no detector
threshold changed. `schemas/threat_alert.py` is byte-identical — blob
`0b087a49`, SHA-256 `81b6c44e…`, 4 824 bytes — and carries the **same blob on
`origin/compiled`**, so the merge could not alter it. `flow_event.py` and
`adapters/ingestion_jsonl.py` (the Zeek boundary) are both untouched.

---

## 1. What changed, and how the path actually works

The previous gap was that `pub mod netflow` had no consumer. **That is now
closed — but not via PyO3.** The `#[pymodule] ingestion_core` still exports 14
functions and **none is NetFlow**. Instead:

```
raw NetFlow v5/v9 datagram (or v5 in classic PCAP)
  -> ingestion/src/bin/netflow_export.rs        [Rust binary, fn main]
       reuses canonical::output::write_canonical_observations_jsonl
  -> canonical_observations.jsonl  (+ ingestion_complete.json marker)
  -> detection_core.netflow_run                 [offline command]
  -> adapters/canonical_flow.py CanonicalFlowAdapter
  -> schemas/canonical_flow.py CanonicalFlowEvent  (subclass of FlowEvent)
  -> engine.process() -> compatibility.canonical_skip_reason() gate
  -> ddos detector -> ThreatAlert v1.1
```

`netflow_export` is auto-discovered by Cargo from `src/bin/`, so it needs no
`[[bin]]` stanza. Canonical data is never rewritten as `features.jsonl`; this
is a second, parallel adapter path, and the legacy Zeek command is unchanged.

## 2. What reaches Detection, per field

Measured by running Advitya's own committed goldens
(`ingestion/tests/fixtures/export/netflow_v5/canonical/*.canonical.jsonl`)
through the real `CanonicalFlowAdapter`:

| FlowEvent field | value | source |
|---|---|---|
| type | `CanonicalFlowEvent` | subclass of `FlowEvent` |
| `timestamp` | `1697120902.3994567` | `data.start_time` |
| `src_ip` / `src_port` | `192.0.2.10` / `12345` | present |
| `dst_ip` / `dst_port` | `198.51.100.20` / `443` | present |
| `proto` | `'tcp'` | from `ip_protocol` |
| `duration` | `1145324.612` | `end_time - start_time` |
| `orig_pkts` | `16909060` | `counters.src_to_dst.packets` |
| `resp_pkts` | **`None`** | no reverse counters |
| `orig_bytes` | **`None`** | only `ip_bytes` exists, not `payload_bytes` |
| `resp_bytes` | **`None`** | no reverse counters |
| `conn_state` | **`None`** | not derived from `tcp_flags` |
| `service` | `None` | not exported |
| `dns` / `tls` / `http` | **`None`** | structurally absent from NetFlow |
| `source` | `'netflow_v5'` | `telemetry_source`, validated |

So **only the 5-tuple, timing, and forward packet count survive.** The record
does carry `tcp_flags` (e.g. `["fin","syn","psh","ack"]`), but no Zeek-style
`connection_state` is derived from them — a deliberate conservative choice,
and the reason `port_scan` is skipped rather than run on a weaker signal.

`CanonicalFlowEvent` relaxes the counters to `int | None` **on the subclass
only**; the strict required fields on `FlowEvent` itself are unchanged.

## 3. Which detectors fire on NetFlow — measured, not assumed

320 synthetic NetFlow v9 canonical records in a SYN-flood shape (320 distinct
sources → one destination, packets only), all 7 detectors registered:

| detector | on NetFlow | reason recorded by the engine |
|---|---|---|
| **`ddos`** | **FIRES** — 320 invocations, **2 alerts** (high + critical), both valid v1.1 | needs `src_to_dst.packets`, which NetFlow has |
| `port_scan` | skipped ×320 | `classified_connection_state_or_responder_payload` |
| `c2_beaconing` | skipped ×320 | `src_to_dst.payload_bytes` |
| `data_exfiltration` | skipped ×320 | `src_to_dst.payload_bytes` |
| `dns_tunnelling` | skipped ×320 | `dns_observations` |
| `encrypted_malware` | skipped ×320 | `tls_observations` |
| `dga_domain` | skipped ×320 | `dns.query` |

`detector_errors: 0`. **One of seven detectors runs on NetFlow.**

Note the distinction worth stating plainly: `dns_tunnelling`,
`encrypted_malware` and `dga_domain` are **structurally impossible** — exported
flow records contain no DNS query strings, no SNI and no JA3/JA3S/JA4, and
nothing can recover them. `port_scan`, `c2_beaconing` and `data_exfiltration`
are **not structurally impossible but deliberately refused**: NetFlow reports
*IP* bytes while those detectors are calibrated on *payload* bytes, and
`port_scan` wants a classified connection state or responder payload. Treating
IP bytes as payload bytes would silently shift every threshold, so the policy
refuses instead. That is the right call, and it is reversible later if the
thresholds are ever re-derived on an IP-byte basis.

### Capability reporting is honest, not silent

Skips are counted per detector per reason in `EngineStats.detector_skips` and
surfaced through `RunStats`. A zero-alert NetFlow run is therefore
distinguishable from a stalled one: the run reports six detectors skipped with
named missing features, rather than appearing to have checked for all seven.

## 4. Robustness

The canonical adapter is **fail-closed** — `"Invalid lines are NOT silently
dropped."` Every malformed input tested was rejected with a line-numbered
`ValueError` and **no warnings**: truncated JSON, non-JSON, empty object,
`telemetry_source: zeek`, unknown source, invalid IP, empty counters, unknown
field, bad timestamp, negative packets. Error text deliberately contains no raw
source values.

**Operational implication:** one malformed record aborts the whole run, unlike
the Zeek adapter which skips and counts bad lines. Defensible for
integrity-bound offline ingestion; worth knowing before pointing it at a noisy
real exporter.

`_RateWindow.add` now raises on `CanonicalFlowEvent` rather than publishing
absent counters as 0, so **legacy throughput telemetry is unavailable on the
NetFlow path** by design.

## 5. Zeek vs NetFlow — gained and lost

**Gained:** NetFlow-only environments are supported at all. Where no PCAP or
Zeek deployment exists — the common case for router/switch flow export — the
pipeline now produces real, provenance-bound DDoS alerts. Each alert carries a
`canonical_trigger` in its evidence (`record_id`, `telemetry_source`,
`sensor_id`, `quality`, `provenance`, `source_record_id`), so a finding traces
back to the exact exported datagram.

**Lost:** six of seven detectors, and the throughput panel. NetFlow is a
reduced-fidelity source: no DNS, no TLS, no payload bytes, no connection state.
The Zeek path remains the full-capability path and the one the evaluation
numbers describe.

> A NetFlow capture is **not** a demonstration of the seven-detector system.
> It demonstrates one detector on a reduced-fidelity feed. The `ddos`
> thresholds on this path are demo heuristics, as `NETFLOW_E2E.md` states.

## 6. No regression

* **Detection suite: 1 968 passed, 0 failures** (baseline 1 843; +125 from
  Advitya's new `test_canonical_flow_adapter.py` and
  `test_netflow_compatibility.py`).
* **Zeek path bit-identical to the pre-merge run**: 2 041/2 041 parsed, 0
  skipped, **16 alerts**, 0 detector errors, 7/7 classes, and the same
  distribution — `c2_beaconing` 3, `data_exfiltration` 1, `ddos` 3,
  `dga_domain` 1, `dns_tunnelling` 1, `encrypted_malware` 3, `port_scan` 4;
  severities critical 6 / high 4 / low 3 / medium 3. All 16 validate at
  `schema_version 1.1`.
* **`tools/verify_e2e.py`: 30/30 checks passed**, throughput telemetry and
  kill-chain correlation included.

The `ActivityWindow` accessors in `aggregators/sliding_window.py` now return
`int | None` instead of coercing unmeasured counters to 0 — correct, since
zero bytes measured and bytes not measured are different facts. The Zeek path
is unaffected because its counters are never `None`, which the 1 968-test pass
and the identical 16-alert run both confirm.

## 7. Not verified here

**No Rust toolchain, Zeek, or Docker on this machine.** Therefore:

* `cargo build --bin netflow_export` was **not** run, and the raw-datagram →
  canonical-JSONL leg is verified by source reading and by Advitya's committed
  canonical goldens — not by executing his binary.
* His Rust test suites (`netflow_v5_*`, `netflow_v9_*`, `template_registry`,
  `netflow_export_cli_tests.rs`) and the PowerShell golden harnesses were not
  executed.
* `ingestion/pytests/test_netflow_detection_e2e.py` invokes the Rust binary and
  so could not run either.

Everything on the Python side — adapter, schema, compatibility gate, engine,
detectors, alert validation — was executed directly, which is the half that
lives in the detection layer.

## 8. Still needed from Advitya

1. **Confirm `cargo build --bin netflow_export` and the Rust/PowerShell suites
   pass on a machine with the toolchain.** This is the one leg nobody has
   executed in this verification.
2. **`NETFLOW_E2E.md` records a Windows-only test that raises on Linux.** He
   documents it honestly and asks for a Linux rerun with that test deselected;
   that rerun is still outstanding.
3. **Optional, not blocking:** a `connection_state` derived from `tcp_flags`
   would let `port_scan` run on NetFlow. It needs a stated, tested mapping —
   not a guess — and is a post-submission item.

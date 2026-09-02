# Detector evaluation on real captured traffic

Every number in this document comes from **real network captures**, not from
`tools/synth_flows.py`. It exists because the synthetic evaluation
(`docs/ML_E2E.md`) could not answer the question that decides whether this
architecture is deployable: *what does it do on traffic nobody generated for
it?*

The headline is that the answer differs sharply by detector, and the detector
that looked best on synthetic traffic is the one that fails hardest on real
traffic.

**No `detection_core` internals were modified.** The detectors, `ThreatAlert
v1.1` and the schemas are byte-identical to `compiled`; all four tools added
here live in `tools/`.

---

## 1. Feasibility: the ingestion pipeline cannot run here

The documented path is `PCAP → Zeek → ingestion_core (Rust) → features.jsonl`.
None of it is available in this environment:

| requirement | status |
|---|---|
| `cargo` / `rustc` | **absent** (checked in the shell and on the Windows side) |
| `maturin` | **absent** — so `ingestion_core` cannot be built |
| `zeek` | **absent**, and no Zeek install directory exists |
| `docker` | **absent** — so `scripts/run_zeek.sh` cannot run either |
| `tshark` / `tcpdump` / `editcap` | **absent** — no PCAP can even be read natively |
| `import ingestion_core` | **ModuleNotFoundError** |
| any `.pcap` in the repo | none |

So **no PCAP was processed, and no `features.jsonl` in this evaluation came
from the real ingestion pipeline.** What was done instead is described in §3.

### What has to happen outside this sandbox

To evaluate the *ingestion + detection* path end to end on a real PCAP, on a
machine with a Rust toolchain and Docker:

```bash
# 1. build the Rust extension
cd ingestion && pip install maturin && maturin develop --release

# 2. run Zeek over a real capture (Docker image; --ja4 for the JA4 column)
sudo ./scripts/run_zeek.sh /path/to/capture.pcap zeek_output

# 3. produce features.jsonl through the REAL pipeline
python pipeline.py --skip-zeek --keep-logs zeek_output -o features.jsonl --stats

# 4. feed it to detection exactly as this evaluation did
cd ../detection && python -m detection_core.runner ../features.jsonl \
    --dga-model ../artifacts/dga_model.joblib --output alerts.jsonl
```

Only step 3 is missing here. Everything from step 4 onward **was** exercised on
real traffic below, so what is untested is the ingestion mapping, not the
detection engine.

---

## 2. What real data was obtained, and what was blocked

Network egress is filtered by a TLS-intercepting proxy. Some hosts resolve and
serve; others present a certificate that fails verification against both
Python's bundled store and the Windows certificate store, which is what an
egress deny-list looks like from inside.

| dataset | reachable? | what happened |
|---|---|---|
| **CIC-IDS2017** via `rdpahalavan/CIC-IDS2017` (Hugging Face) | **yes** | `Network-Flows/CICIDS_Flow.parquet`, **370 MB, 2 827 677 real flows**, downloaded and used |
| **UNSW-NB15** via Zenodo record `10140548` | **yes** | `UNSW-NB15_1.csv`, **169 MB, 700 001 real flows**, downloaded and used |
| DGA family domains (`baderj/domain_generation_algorithms`) | **yes** | 9 of 13 untrained families fetched; 4 returned HTTP 404 |
| Cisco Umbrella top 1M | **yes** | 12.7 MB, used as the real benign DNS population |
| **CIC-IDS2017 official** (`unb.ca`, `cicresearch.ca`) | **no** | `CERTIFICATE_VERIFY_FAILED: self-signed certificate in certificate chain`; plain-HTTP URLs fail the same way, i.e. intercepted |
| **CTU-13** (`mcfp.felk.cvut.cz`) | **no** | `CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate` |
| real PCAPs (malware-traffic-analysis.net, Netresec, MAWI) | hosts reachable | **unusable** — no `tshark`/Zeek to convert a PCAP to flows |

CTU-13 being blocked is the significant loss: it is real *captured botnet*
traffic and would have been the best available evidence for `c2_beaconing` and
DGA. The Hugging Face mirror of CIC-IDS2017 partly compensates because its
`Bot` class is a real Ares botnet capture.

---

## 3. How real traffic reached the detectors

Both datasets ship as **flow records**, which is the same level the ingestion
pipeline emits, so they were mapped onto the `features.jsonl` schema and fed to
the **real, unmodified `detection_core.runner`**:

```bash
python tools/cicids_to_features.py CICIDS_Flow.parquet --day 03/07/2017 \
    --require-seconds -o data/real_benign_monday.jsonl
cd detection && python -m detection_core.runner ../data/real_benign_monday.jsonl \
    --dga-model ../artifacts/dga_model.compiled_baseline.joblib \
    --output ../data/real_benign_monday.alerts.jsonl
```

**Three detectors cannot be evaluated this way at all.** Flow-level datasets
carry no DNS query strings and no TLS fingerprints, so `dga_domain`,
`dns_tunnelling` and `encrypted_malware` are structurally unable to fire. They
are reported as **N/A**, never as "0 false positives" — a zero a detector could
not have exceeded is not a result. `dga_domain` is instead evaluated directly
on real domains in §6.

Two further limitations, both material:

* **CIC-IDS2017 timestamp resolution is inconsistent.** The Monday (benign)
  capture has full **second** resolution; **every attack day is quantised to
  the minute**. Minute quantisation destroys inter-arrival structure, so the
  Friday `c2_beaconing` numbers are indicative only. The benign FPR — the
  headline number — is unaffected, because Monday has seconds.
* **Flow definition is CICFlowMeter's / UNSW's, not Zeek's.** Per-flow
  behaviour transfers; absolute flow counts do not.

---

## 4. Real false-positive rate — the number we did not have

**CIC-IDS2017, Monday 03/07/2017 — 529 450 flows over 12 h, 100 % benign.**
On a purely benign capture every alert is a false positive by construction. No
labels, no threshold argument, no attribution heuristic.

| detector | false positives | per 1 000 flows | per hour | distinct sources | severity |
|---|---|---|---|---|---|
| **`port_scan`** | **1 636** | **3.0900** | **136.3** | 243 | 732 low, 442 med, 278 high, **184 critical** |
| `c2_beaconing` | 157 | 0.2965 | 13.1 | 11 | 26 low, 53 med, **76 high, 2 critical** |
| `ddos` | 5 | 0.0094 | 0.4 | 1 | 5 low |
| `data_exfiltration` | **0** | **0.0000** | 0.0 | 0 | — |
| `dns_tunnelling` | N/A | N/A | N/A | N/A | no DNS in this data |
| `dga_domain` | N/A | N/A | N/A | N/A | no DNS in this data |
| `encrypted_malware` | N/A | N/A | N/A | N/A | no TLS in this data |
| **total** | **1 798** | **3.3960** | **149.8** | | |

**UNSW-NB15 (different testbed, 2015) agrees**: 1 715 benign-window false
positives over 699 934 flows = **2.45 per 1 000**, again dominated by
`port_scan` (1 171) and `c2_beaconing` (544). Two independent networks, same
shape of failure.

At 136 `port_scan` alerts an hour, **184 of them `critical`**, an analyst
queue fed by this detector is unusable on a real network.

---

## 5. Real precision / recall where labels exist

Recall is measured over **episodes** — distinct (class, attacking entity)
pairs — not flows, because these detectors aggregate per host by design and
per-flow recall would punish them for that. Precision counts only benign
false positives in the denominator; alerts landing on attacks the suite does
not claim (exploits, fuzzers, web attacks) are reported separately.

**UNSW-NB15 — 699 934 flows, 7.91 h, epoch-second timestamps**

| detector | episodes | found | recall | TP | FP (benign) | precision | F1 | FP/1k flows |
|---|---|---|---|---|---|---|---|---|
| `port_scan` | 4 | 4 | **1.000** | 14 | 1 171 | **0.012** | 0.023 | 1.673 |
| `c2_beaconing` | 4 | 2 | 0.500 | 2 | 544 | **0.004** | 0.007 | 0.777 |
| `ddos` | 10 | 0 | **0.000** | 0 | 0 | — | — | 0.000 |
| `data_exfiltration` | 0 | — | — | 0 | 0 | — | — | 0.000 |

**CIC-IDS2017 Friday 07/07/2017 — 702 713 flows, minute-resolution timestamps**

| detector | episodes | found | recall | TP | FP (benign) | FP (cross) | precision | FP/1k |
|---|---|---|---|---|---|---|---|---|
| `port_scan` | 1 | 1 | **1.000** | 16 | 748 | 124 | **0.018** | 1.241 |
| `c2_beaconing` | 8 | 6 | **0.750** | 92 | 609 | 1 007 | **0.054** | 2.300 |
| `ddos` | 2 | 0 | **0.000** | 0 | 5 | 0 | 0.000 | 0.007 |
| `data_exfiltration` | 0 | — | — | 0 | 0 | 2 | — | 0.003 |

`c2_beaconing` finding **6 of 8** real Ares-botnet C2 sources is a genuine
positive result — the detector does catch real command-and-control.

### Why `ddos` recall is 0.000, and why that is not a bug

The detector requires **≥ 50 unique sources**, ≥ 200 flows and ≥ 1 000 packets
inside a **10-second** window — the signature of a spoofed-source volumetric
flood. Neither dataset's "DoS/DDoS" is that shape:

| dataset | label | victim | flows | **distinct sources** | rate |
|---|---|---|---|---|---|
| UNSW-NB15 | DoS | 149.171.126.12 | 552 | **4** | 0.1 flows/s |
| CIC-IDS2017 | DDoS | 192.168.10.50 | 128 022 | **2** (LOIC) | — |

Both are low-source-count / application-layer DoS. The detector declining to
call 4 sources a *distributed* flood is correct behaviour. The honest
conclusion is not "recall 0" but: **volumetric DDoS recall remains unmeasured
on real traffic, and the detector is blind to low-source and application-layer
DoS** — a real coverage gap, since that is the more common attack today.

---

## 6. `dga_domain` on real domains

Evaluated directly, since its input is a domain name and real ground truth
exists. **Positives**: 783 domains from **9 real malware families the model was
never trained on** (bumblebee, monerodownloader, padcrypt, darkcracks,
dnschanger, orchard, verblecon, and two unnamed downloaders). **Negatives**:
39 591 hostnames sampled at random from the **Cisco Umbrella top 1M** — what
public resolvers actually saw — with every domain from the training CSVs
removed.

| model | ROC-AUC | PR-AUC | P@0.75 | R@0.75 | **FP per 1 000 real hostnames** |
|---|---|---|---|---|---|
| corpus as on `compiled` | 0.8220 | 0.0718 | 0.0767 | 0.7880 | **187.6** |
| corpus + real CDN hostnames | **0.9201** | **0.2806** | **0.3779** | 0.7612 | **24.8** |

Two findings:

1. **The shipped-on-`compiled` model flags 18.8 % of all real resolver-observed
   hostnames as DGA.** That is not deployable. The synthetic evaluation could
   not see this because synthetic benign DNS is six hostnames and four CDN
   confounders.
2. **The CDN-corpus fix (`integration/dga-precision`) is independently
   validated on real data**: false positives fall **7.6×**, ROC-AUC
   0.822 → 0.920, PR-AUC 0.072 → 0.281 (3.9×), at a 2.7-point recall cost.

**PR-AUC 0.28, not the 0.84 the training report shows.** Both are correct; they
measure different things. The training split is ~36 % positive, real DNS is
~2 %, and average precision moves with the positive rate. **0.28 is the number
to quote for deployment.**

Per-family recall @0.75 shows where it fails — the families it misses are the
dictionary-style ones, exactly the known limit in `docs/dga_model.md`:

| family | n | recall | | family | n | recall |
|---|---|---|---|---|---|---|
| verblecon | 1 | 1.000 | | darkcracks | 31 | 0.452 |
| bumblebee | 100 | 0.950 | | dnschanger | 5 | 0.400 |
| monerodownloader | 500 | 0.936 | | unnamed_javascript_dga | 30 | 0.367 |
| padcrypt | 24 | 0.750 | | orchard | 32 | 0.250 |
| | | | | **unnamed_downloader** | 60 | **0.000** |

---

## 7. Real vs synthetic — where it diverges

Both FP columns are measured the same way — a benign-only capture, every alert
a false positive — so they are directly comparable. The synthetic column is
28 491 benign+confounder flows from `tools/synth_flows.py`; the real column is
the 529 450-flow CIC-IDS2017 Monday.

| detector | synth precision | **real precision** | synth FP/1k benign | **real FP/1k benign** | verdict |
|---|---|---|---|---|---|
| **`port_scan`** | **1.000** | **0.012 – 0.018** | **0.0000** | **3.0900** | **collapses — 0 → 1 636 alerts** |
| `c2_beaconing` | 0.241 – 0.489 | 0.004 – 0.054 | 0.4563 | 0.2965 | FP rate comparable; **precision far worse** |
| `ddos` | 1.000 | — (no matching shape) | 0.0000 | 0.0094 | clean, but **coverage gap exposed** |
| `data_exfiltration` | 1.000 | — (no labelled exfil) | 0.0000 | **0.0000** | **holds up** |
| `dga_domain` | 1.000 (after fix) | PR-AUC 0.281 | 1.8602 | **24.8 per 1k domains** | **synthetic wildly optimistic** |
| `dns_tunnelling` | 0.741 | not measurable | 0.0000 | not measurable | **unknown on real data** |
| `encrypted_malware` | 1.000 | not measurable | 0.0000 | not measurable | **unknown on real data** |

`c2_beaconing` is the interesting non-divergence: its *false-positive rate per
flow* is the same order on both (0.46 synthetic vs 0.30 real), because the NTP
confounder was doing its job. What synthetic could not show is that real
precision is an order of magnitude worse — there are only a handful of real
attacks to be right about, and hundreds of benign periodic sources to be wrong
about, so the same FP rate buys a far worse ratio.

### `port_scan`: the finding that matters

Perfect on synthetic — precision 1.000, recall 1.000, **zero** false positives
across 260 trials — and **1 636 false positives in 12 hours** of real benign
traffic, 184 of them `critical`. Two distinct mechanisms, both visible in the
alert evidence:

**Horizontal (936 of 1 636) — this is ordinary web browsing.**
```
src=192.168.10.5  scan_type=horizontal  unique_dst_ports=3
unique_dst_ips=98  connection_attempts=674  window=60s  -> score 1.000 CRITICAL
```
A workstation contacting **98 distinct IPs on ports 443/53/80 in one minute** is
a browser loading pages whose assets are spread across CDNs. The rule "one
source, few ports, many hosts" *is* the shape of normal HTTPS browsing. The
synthetic benign generator never produced this: `benign_web` contacts a single
`/24` and the authorised-scan confounder was deliberately tuned to sit *below*
threshold, so the case was never in the test set.

**Vertical (697) — this is inbound server traffic.**
```
src=162.208.20.178 -> 192.168.10.5  unique_dst_ports=121  window=60s -> 1.000 CRITICAL
```
A remote host hitting 121 distinct **ephemeral** ports is the reply side of the
LAN host's own connections. The detector counts distinct `dst_port` without
separating ephemeral (> 1024) from service ports.

Neither is a threshold-tuning problem. Both need a signal the detector does not
currently use — connection *failure* (Zeek's `S0`/`REJ`), which is what
actually distinguishes a scan from a busy client. **That signal exists in
Zeek's `conn_state` and is absent from both public datasets, which is why this
evaluation can prove the false-positive rate but cannot prove the fix.**

### `c2_beaconing`: synthetic understated the problem

The synthetic run already flagged this detector (precision 0.241) via the NTP
confounder at CoV 0.004. Real traffic is worse — 0.004–0.054 precision — and
shows why:
```
192.168.10.14 -> 69.28.157.213:443   75 observations, mean interval 6.03s, CoV 0.038 -> CRITICAL
192.168.10.19 -> 93.184.216.172:443   8 observations, mean interval 120.0s, CoV 0.000 -> HIGH
```
Real networks are full of periodic HTTPS: telemetry, keepalives, polling,
streaming heartbeats. The synthetic capture had exactly **one** benign periodic
source (NTP); a real one has hundreds.

---

## 8. What these numbers prove, and what they do not

**They prove:**
* The detection engine runs unmodified on real traffic at ~4 600 flows/s, and
  parsed 1.93 M real flows with **0 adapter errors and 0 detector errors**.
* `port_scan` as written is not deployable on a real network without a
  connection-failure signal. This is measured, not argued.
* `c2_beaconing` has no benign-periodicity discrimination — confirmed on two
  independent real networks.
* `data_exfiltration` produced **zero** false positives on 1.23 M real benign
  flows across both datasets.
* The DGA CDN-corpus fix is real and large (7.6× fewer false positives on
  resolver-observed hostnames).

**They do not prove:**
* **Anything about `dns_tunnelling` or `encrypted_malware`** on real traffic.
  Neither can fire without DNS/TLS fields that flow-level datasets do not carry.
* **Anything about the ingestion layer**, which never ran.
* **A deployment false-positive rate.** CIC-IDS2017 (2017) and UNSW-NB15 (2015)
  are university testbeds with generated benign traffic, not the network this
  will run on. The *shape* of the failures transfers; the exact rate will not.
* **Anything about real-world volumetric DDoS**, whose signature is absent from
  both datasets.
* Attack traffic in both datasets is **tool-generated** (LOIC, nmap, IXIA
  PerfectStorm), not malware captured in the wild. The `Bot` class in
  CIC-IDS2017 is the closest to real, and it is where `c2_beaconing` earned its
  0.750 recall.

Dataset age is a genuine caveat: 2015 and 2017 predate TLS 1.3 ubiquity,
QUIC/HTTP-3, and the current CDN topology — all of which make the `port_scan`
horizontal false positive *worse* today, not better, since a modern page load
touches more distinct hosts than a 2017 one.

---

## 9. What must happen on a real machine

For the team, in priority order:

1. **A benign capture from the actual deployment network**, run through the
   real ingestion pipeline. It is the only way to get a deployment FPR, and
   §4 shows the number is not small enough to guess at.
2. **Ingestion environment** (`cargo` + `maturin` + Docker/Zeek) so
   `PCAP → features.jsonl` can be exercised. Until then the ingestion mapping
   is untested against detection, and `tls.ja4` remains unimplemented (see
   `docs/ML_E2E.md` §5).
3. **A capture with DNS and TLS** so `dns_tunnelling` and `encrypted_malware`
   can be evaluated at all. Zeek's `dns.log` and `ssl.log` from any real
   capture would do; this is the largest coverage hole in this report.
4. **CTU-13**, from a network that can reach `mcfp.felk.cvut.cz` — real
   captured botnet traffic with PCAPs, the best available evidence for
   `c2_beaconing` and DGA together.
5. **`conn_state` end to end.** The `port_scan` fix depends on it, and
   `ingestion/src/features/flow.rs` still has no `S0` arm
   (`docs/ML_E2E.md` §5, item 5).

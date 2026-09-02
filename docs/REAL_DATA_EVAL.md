# Detector evaluation on real captured traffic

Every number in this document comes from **real network captures**, not from
`tools/synth_flows.py`. It exists because the synthetic evaluation
(`docs/ML_E2E.md`) could not answer the question that decides whether this
architecture is deployable: *what does it do on traffic nobody generated for
it?*

The headline is that the answer differs sharply by detector, and the detector
that looked best on synthetic traffic is the one that fails hardest on real
traffic.

`ThreatAlert v1.1` and every schema are **byte-identical to `compiled`** and
stay that way: the full-stack team builds against that contract. §1-§9 below
were written before any detector changed, and measure the detectors exactly as
`compiled` ships them.

**§10 is the sequel.** Two of the failures §4-§7 diagnosed - `port_scan`'s
1 636 false positives and `c2_beaconing`'s periodic-by-design noise - were then
fixed in detector logic and re-measured on the same captures. Where a figure in
§4-§5 was corrected by that re-run it is marked; the corrections are small and
in one detector, and §10 says which.

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
| `c2_beaconing` | 156 | 0.2946 | 13.0 | 11 | 26 low, 53 med, **75 high, 2 critical** |
| `ddos` | 5 | 0.0094 | 0.4 | 1 | 5 low |
| `data_exfiltration` | **0** | **0.0000** | 0.0 | 0 | — |
| `dns_tunnelling` | N/A | N/A | N/A | N/A | no DNS in this data |
| `dga_domain` | N/A | N/A | N/A | N/A | no DNS in this data |
| `encrypted_malware` | N/A | N/A | N/A | N/A | no TLS in this data |
| **total** | **1 797** | **3.3941** | **149.8** | | |

> Corrected by the §10 re-run: the `c2_beaconing` row first read 157, total
> 1 798. Re-running the identical `compiled` code over the identical capture
> gives 156, twice over, so the extra alert came from that earlier run and not
> from the detector. No other row moved.

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
| `c2_beaconing` | 4 | 1 | 0.250 | 1 | 544 | **0.002** | 0.004 | 0.777 |
| `ddos` | 10 | 0 | **0.000** | 0 | 0 | — | — | 0.000 |
| `data_exfiltration` | 0 | — | — | 0 | 0 | — | — | 0.000 |

**CIC-IDS2017 Friday 07/07/2017 — 702 713 flows, minute-resolution timestamps**

| detector | episodes | found | recall | TP | FP (benign) | FP (cross) | precision | FP/1k |
|---|---|---|---|---|---|---|---|---|
| `port_scan` | 1 | 1 | **1.000** | 16 | 748 | 124 | **0.018** | 1.241 |
| `c2_beaconing` | 8 | 6 | **0.750** | 90 | 585 | 1 007 | **0.054** | 2.266 |
| `ddos` | 2 | 0 | **0.000** | 0 | 5 | 0 | 0.000 | 0.007 |
| `data_exfiltration` | 0 | — | — | 0 | 0 | 2 | — | 0.003 |

`c2_beaconing` finding **6 of 8** real Ares-botnet C2 sources is a genuine
positive result — the detector does catch real command-and-control.

> Both `c2_beaconing` rows are corrected the same way as §4. Re-running
> `compiled` unchanged gives UNSW **1** episode found / 1 TP (not 2 / 2) and
> Friday **90** TP / **585** benign FP (not 92 / 609). Every `port_scan`,
> `ddos` and `data_exfiltration` figure reproduced exactly. The conclusion is
> unchanged — UNSW recall was poor and is poor — but 0.250 is the number that
> reproduces, so it is the baseline §10 measures against.

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
| `c2_beaconing` | 0.241 – 0.489 | 0.002 – 0.054 | 0.6318 | 0.2946 | FP rate same order; **precision far worse** |
| `ddos` | 1.000 | — (no matching shape) | 0.0000 | 0.0094 | clean, but **coverage gap exposed** |
| `data_exfiltration` | 1.000 | — (no labelled exfil) | 0.0000 | **0.0000** | **holds up** |
| `dga_domain` | 1.000 (after fix) | PR-AUC 0.281 | 2.6324 | **24.8 per 1k domains** | **synthetic wildly optimistic** |
| `dns_tunnelling` | 0.741 | not measurable | 0.0000 | not measurable | **unknown on real data** |
| `encrypted_malware` | 1.000 | not measurable | 0.0000 | not measurable | **unknown on real data** |

`c2_beaconing` is the interesting non-divergence: its *false-positive rate per
flow* is the same order on both — 0.63 synthetic vs 0.30 real, i.e. synthetic
was actually the *noisier* of the two — because the NTP confounder was doing
its job. What synthetic could not show is that real precision is an order of
magnitude worse: there are only a handful of real attacks to be right about and
hundreds of benign periodic sources to be wrong about, so the same FP rate buys
a far worse ratio. This is the one detector where the synthetic harness was not
flattering the result.

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

Neither is a threshold-tuning problem. Both need signals the detector does not
currently use: which ports could hold a service at all, and whether the far side
*answered* — connection failure, which is what actually distinguishes a scan
from a busy client.

**Both were then built and measured — see §10.** The answer half is read from
`conn_state` where a capture carries one and from responder payload bytes where
it does not, which is what makes it measurable on datasets that carry no
connection state. UNSW-NB15's own `state` column supplies a real, labelled
stand-in for the field ingestion drops (`tools/unsw_to_features.py`), so §10
can put a number on what that missing field costs as well.

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
* `port_scan` **as `compiled` ships it** is not deployable on a real network:
  1 636 false positives in twelve hours, 184 `critical`. This is measured, not
  argued — and §10 measures the fix the same way, down to 173.
* `c2_beaconing` as `compiled` ships it has no benign-periodicity
  discrimination — confirmed on two independent real networks. §10 removes the
  periodic-by-design services (156 → 89 on Monday) and leaves the rest open.
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
5. **`conn_state` end to end — now with a price tag.** `port_scan` 0.3.0 reads
   it and falls back to a responder-payload proxy without it, and §10.5
   measures what that costs: **recall 0.500 against 1.000** on UNSW-NB15's
   Reconnaissance episodes, because banner-grabbing recon completes its
   connections and only the connection state gives it away. The blocker is
   unchanged — `encode_conn_state` in `ingestion/src/features/flow.rs` has no
   `S0` arm, so `S0` arrives as `0`, the same code as "unknown"
   (`docs/ML_E2E.md` §5, item 5). Either add the arm, or keep emitting the raw
   `conn_state` string alongside the encoded one, which `pipeline.py` already
   does and the adapter already prefers. Detection needs no further change:
   `tools/ingestion_field_audit.py` reports which states a capture actually
   carries and flags `port_scan` as DEGRADED when none arrive.

---

## 10. The fixes those numbers bought, measured the same way

§4–§7 are a diagnosis: `port_scan` produced **1 636** false positives in twelve
hours of real benign traffic, 184 of them `critical`, and `c2_beaconing` had no
discrimination against benign periodicity. Both detectors were then changed —
`port_scan` 0.2.0 → **0.3.0**, `c2_beaconing` 0.1.0 → **0.2.0** — and re-measured
on the identical captures with the identical scoring tools.

**How the before/after was produced.** `compiled` is checked out into a separate
worktree and driven through `detection_core.runner` unmodified; the working tree
is driven the same way; both alert sets are scored by the *same*
`tools/real_fpr_report.py` and `tools/real_eval.py`. The only variable is
detector code. Every `compiled` figure below reproduced twice.

### 10.1 What changed

**`port_scan` 0.3.0** adds two credibility checks, applied after a window has
already crossed the fan-out thresholds. Neither is a threshold nudge; both bring
in evidence the detector was not reading.

* **Ports a service could live on** (vertical alerts only). A vertical alert
  needs ≥ 3 distinct ports at or below **49151**. Above that is IANA's
  dynamic/private range, which hosts hand out to *outbound* connections —
  nothing is listening there to enumerate. Measured across the 697 benign
  vertical false positives: median service ports **0**, 83.4 % had none at all,
  87.5 % had fewer than three. The weakest window of either *real* scan had 13.
* **The responder has to be refusing** (both scan types). Read from Zeek's
  `conn_state` when the capture carries one, and from responder payload bytes
  when it does not. Measured across the 936 benign horizontal false positives:
  median **86 %** of the window came back with real payload; across the sixteen
  windows of the labelled nmap scan on Friday, at most **9.5 %**. Both
  populations were measured with the rules *disabled* — the run reproduces
  `compiled`'s 888 Friday and 1 636 Monday `port_scan` alerts exactly while
  emitting 0.3.0's evidence — so these are the distributions of the old alert
  set, not of whatever survived.

  **This gate cannot misfire on a unidirectional capture.** With no reverse
  direction there are no responder bytes anywhere, the measured share is 0.0 for
  every window, nothing is suppressed, and the detector behaves exactly as 0.2.0
  did. It spends reply evidence when it exists and asks for none when it does
  not.

**`c2_beaconing` 0.2.0** adds two structural exclusions — relationships that
cannot be a controller check-in at all, decided before the timing window is
built. Neither looks at timing, because timing cannot settle them: a time daemon
is a more regular beacon than most real C2.

* **Periodic-by-design services.** The NTP-only exclusion widens to DHCP
  (67/68), NetBIOS name and datagram (137/138), LDAP, LDAPS and Global Catalog
  (389/636/3268/3269), SSDP (1900), mDNS (5353) and LLMNR (5355). On Monday
  these accounted for **67 of the 156** false positives; 38 were a single domain
  controller.
* **Multicast and broadcast destinations.** A group address is something you
  announce to, not an endpoint you hold a session with.

  **`53` and `445` are deliberately still watched**, though both produce false
  positives. Excluding them was measured rather than assumed: dropping port 53
  costs **36 of the 90** true positives on the labelled Ares-bot capture and an
  entire episode (recall 0.750 → 0.625); dropping 445 costs two more.

### 10.2 False-positive rate on real benign traffic

**CIC-IDS2017 Monday — 529 450 flows over 12 h, 100 % benign, so every alert is
a false positive by construction.**

| detector | before | after | change | per 1 000 before | per 1 000 after |
|---|---|---|---|---|---|
| **`port_scan`** | **1 636** | **173** | **−89.4 %** | 3.0900 | **0.3268** |
| **`c2_beaconing`** | **156** | **89** | **−42.9 %** | 0.2946 | **0.1681** |
| `ddos` | 5 | 5 | — | 0.0094 | 0.0094 |
| `data_exfiltration` | 0 | 0 | — | 0.0000 | 0.0000 |
| **total** | **1 797** | **267** | **−85.1 %** | 3.3941 | **0.5043** |

The severity mix matters as much as the count, because the analyst queue is
sorted by it:

| `port_scan` | low | medium | high | **critical** | distinct sources |
|---|---|---|---|---|---|
| before | 732 | 442 | 278 | **184** | 243 |
| after | 128 | 33 | 6 | **6** | 43 |

136 alerts an hour with 184 criticals becomes **14 an hour with 6**.

### 10.3 Which rule did what

Each rule disabled in turn through `--config`, everything else held constant.
They are complementary, not redundant — neither alone is close.

| `port_scan` on Monday | alerts | vertical | horizontal |
|---|---|---|---|
| both rules off (reproduces `compiled` exactly) | 1 636 | 697 | 936 |
| service-port rule only | 1 041 | 102 | 936 |
| responder rule only | 768 | 681 | 87 |
| **both — what ships** | **173** | **86** | **87** |

The service-port rule removes the ephemeral-sweep verticals; the responder rule
removes the CDN-browsing horizontals. Running with both off reproduces
`compiled`'s alert set exactly, which is also how the distributions above were
measured: the old false positives, carrying the new evidence fields.

The same ablation on `c2_beaconing` says something less flattering, and it is
reported because it is true:

| `c2_beaconing` on Monday | alerts |
|---|---|
| neither exclusion (= `compiled`) | 156 |
| multicast rule only | 126 |
| service-port list only | 89 |
| **both — what ships** | **89** |

**On this capture the multicast rule buys nothing the port list has not already
bought.** All 30 of its suppressions were SSDP to `239.255.255.250`, which is
port 1900 and therefore already excluded. It is kept because it is a different
kind of statement — a multicast group cannot be a controller *whatever* port it
uses — and because the port list is site-editable while that fact is not. But
its measured contribution here is zero, not 30.

### 10.4 Precision and recall where labels exist

Recall is per **episode** — (class, attacking entity) — exactly as in §5.

**CIC-IDS2017 Friday — 702 713 flows, minute-resolution timestamps**

| detector | episodes | found b→a | recall b→a | TP b→a | FP benign b→a | precision b→a |
|---|---|---|---|---|---|---|
| **`port_scan`** | 1 | 1 → 1 | **1.000 → 1.000** | 16 → 16 | **748 → 87** | **0.018 → 0.131** |
| `c2_beaconing` | 8 | 6 → 6 | **0.750 → 0.750** | 90 → 90 | 585 → 526 | 0.054 → 0.056 |
| `ddos` | 2 | 0 → 0 | 0.000 → 0.000 | 0 → 0 | 5 → 5 | 0.000 → 0.000 |
| `data_exfiltration` | 0 | — | — | 0 → 0 | 0 → 0 | — |

**Recall did not move on either detector.** `port_scan` precision improves 7.3×.
`c2_beaconing`'s barely moves, because minute-quantised timestamps leave it
1 000 cross-attack alerts that no exclusion here touches.

**UNSW-NB15 — 699 934 flows, run twice: once carrying the `conn_state` column
ingestion does not emit today, once without it.**

| detector | recall b→a | TP b→a | FP benign b→a | precision b→a |
|---|---|---|---|---|
| `port_scan`, **no** `conn_state` | 1.000 → **0.500** | 14 → 2 | **1 171 → 0** | 0.012 → **1.000** |
| `port_scan`, **with** `conn_state` | 1.000 → **1.000** | 14 → 11 | **1 171 → 0** | 0.012 → **1.000** |
| `c2_beaconing` (either) | 0.250 → 0.250 | 1 → 1 | 544 → 378 | 0.002 → 0.003 |

Running `compiled` over the `conn_state` capture produces a **byte-identical**
alert set to running it without — 1 730 alerts either way — which is the control
proving the field was doing nothing at all before this change.

### 10.5 The one real cost, stated plainly

**Without `conn_state`, `port_scan` recall on UNSW-NB15 halves: 1.000 → 0.500.**

The four labelled Reconnaissance episodes are banner-grabbing recon: they
*complete* their connections, roughly 58 % `SF` against 42 % `S0`. The byte
proxy sees a conversation and stays quiet; only the connection state says
otherwise. With the state, the separation is total and one-sided:

| UNSW-NB15 windows | n | incomplete fraction | established fraction |
|---|---|---|---|
| benign — every window 0.2.0 alerted on | 1 171 | max **0.0235** | min **0.9636** |
| the four real Reconnaissance episodes | 14 | median 0.163, **9 ≥ 0.05** | median 0.837 |

Not one benign window in 1 171 reaches the 0.05 threshold; nine scan windows do,
spread across all four episodes — which is how recall 1.000 and precision 1.000
happen together.

CIC-IDS2017's nmap scan needs no such help: it is refused outright, at most
9.5 % answered, so on that capture recall holds at 1.000 on the proxy alone.
**The gap is specifically banner-grabbing recon, and `conn_state` is what closes
it.** See §9 item 5 for what that asks of ingestion.

### 10.6 What did not change

* **`ThreatAlert` v1.1 is byte-identical to `compiled`** — same git blob hash,
  `0b087a49`. Alerts carry four extra keys *inside* the existing free-form
  `evidence` object (`service_ports`, `responder_evidence`,
  `incomplete_fraction`, `established_fraction`), which is what that object is
  for. Every alert in every run above validates against v1.1 and round-trips
  through `to_wire`.
* **The synthetic behaviour matrix is unchanged**, cell for cell. `compiled`
  and this branch were both run over 20 seeded captures — 1 820 detector×slice
  trials, `tools/detector_matrix.py` — and every detector returns the same
  numbers: `port_scan` 40 TP / 0 FP, `c2_beaconing` 20 / 15, `dns_tunnelling`
  20 / 7, the other four 20 / 0. None of the four planted confounders changed
  side. Whatever these rules do on real traffic, they do nothing to the
  synthetic evaluation `docs/ML_E2E.md` reports.
* **The demo capture is unchanged**: 2 041 flows → 16 alerts, all seven
  detectors firing, identical counts before and after.
* `ddos`, `data_exfiltration`, `dns_tunnelling`, `encrypted_malware` and
  `dga_domain` are untouched, and their figures are unchanged everywhere they
  were measurable.

### 10.7 What these numbers still do not prove

Everything in §8 still applies — these are public flow datasets mapped onto the
features shape, **not** a capture from the deployment network run through the
real ingestion pipeline. Specifically:

* **The reduction is measured on 2015 and 2017 university testbeds.** The
  *mechanism* transfers — ephemeral-port replies and answered browsing exist on
  every network — but the exact 89 % will not.
* **`c2_beaconing` is improved, not fixed.** 89 false positives in twelve hours
  at precision 0.056 is still a lead generator, not a verdict. What remains is
  periodic HTTPS and HTTP to ordinary internet hosts, and no port list or
  address rule reaches it. A **destination-popularity** rule was measured and
  rejected: the real Ares controller had a fan-in of 5 internal hosts while the
  surviving benign destinations span 1–25, so the controller sits *inside* the
  benign distribution, and the only cut that spares it — "6 or more" — is a fact
  about a ten-host lab rather than about C2.
* **`port_scan` at full strength depends on ingestion**, and that dependency is
  now quantified rather than asserted: 0.500 recall against 1.000.

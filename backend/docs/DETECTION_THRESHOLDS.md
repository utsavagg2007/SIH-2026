# Evidence threshold registry

## Why this file exists

The Frontend Design Specification §5.1 asks each evidence row to show "how far
past the line the value landed". That needs three things the frozen v1.1 alert
does not carry:

* a **threshold**,
* which **direction** across it is bad,
* a **scale** to draw the bar against.

The detection layer *could* ship these, but the alert spec deliberately keeps
`evidence` as a flat bag so detectors can add keys without a schema bump. So the
knowledge lives in `app/projection/thresholds.py`, keyed by evidence feature
name and scoped by threat class where the same name means different things.

## Precedence

1. **A detector-supplied threshold always wins.** If evidence contains
   `<feature>` and `<feature>_threshold`, the detector is telling us its actual
   operating point, and that beats this table every time. The `_threshold` key
   is consumed, not rendered as its own row.
2. **Otherwise the registry entry applies**, if the feature is registered for
   that threat class, or in the small shared table.
3. **Otherwise the feature renders as a plain label/value pair with no bar.**
   Spec §5.1: "Do not invent a scale to make them look uniform." We never
   fabricate a threshold to make a row look decisive.

That third case is a supported outcome, not a gap. A brand-new evidence key
appears on the dashboard the day a detector starts emitting it, with a
humanised label and no bar, without anyone editing this file first.

## Two rules for whoever tunes these

**These are placeholders until the detection team confirms them.** The values
below are the operating points the detectors are *expected* to use. They were
chosen to be defensible, not measured. Before demo day they should be
reconciled with the thresholds the detectors actually fire at — otherwise the
dashboard will draw a line in a different place than the detector drew it, and
an evidence bar that says "0.04, threshold 0.15" while the detector fired at
0.20 is worse than no bar at all.

**The preferred fix is not to edit this file.** It is for detectors to ship
`<feature>_threshold` in evidence. Then the bar always matches the decision,
automatically, for every detector version — and this table degrades to a
fallback for keys nobody has gotten to yet.

## Direction is not always "above"

Three features are inverted, and getting the sign wrong makes the bar say the
opposite of what the detector meant:

| Feature | Direction | Why |
|---|---|---|
| `interval_cv` | **below** | Coefficient of variation near zero means near-perfect regularity. This is the decisive beaconing feature and the one where *low* is bad. |
| `interval_stddev_sec`, `jitter_pct`, `payload_size_cv` | **below** | Same reasoning: automated check-ins are consistent, humans are not. |
| `ngram_score` | **below** | Low likelihood against the legitimate-domain corpus is what makes a domain suspicious. |
| `ja3_frequency` | **below** | A fingerprint seen twice in the whole baseline is the signal; one seen ten thousand times is a browser. |
| `cert_validity_days` | **below** | Short-lived certificates are the indicator. |

Everything else is `above`.

## Flag-style features

Booleans are registered with a threshold of `0.5` and direction `above`, so
`self_signed: true` or `destination_novel: true` renders as a crossed line
rather than being silently skipped. `app/projection/evidence.py` coerces
booleans to 1.0/0.0 for this comparison only; the displayed value stays
`yes`/`no`.

## Registry contents

Full values live in `app/projection/thresholds.py`. Summary of the decisive
feature per class — the one ranked first, which the frontend shows at the top:

| Threat class | Most decisive feature | Threshold | Direction |
|---|---|---:|---|
| `port_scan` | `unique_dst_ports` | 100 | above |
| `ddos` | `flows_per_sec` | 1000 | above |
| `ddos` (amplification) | `amplification_factor` | 10× | above |
| `c2_beaconing` | `interval_cv` | 0.15 | **below** |
| `dga_domain` | `ngram_score` | 0.2 | **below** |
| `dns_tunnelling` | `query_length` | 60 chars | above |
| `encrypted_malware` | `ja3_rarity` | 0.9 | above |
| `data_exfiltration` | `out_in_byte_ratio` | 5.0× | above |

For DDoS, `source_ip_entropy` (threshold 6.0 bits, above) is the feature that
separates the two flood shapes and the one a judge is most likely to ask about:

* **high entropy + no completed handshakes** → spoofed sources
* **low entropy + high volume** → a direct flood from real hosts

The registry threshold marks the spoofing side, which is the more common case.
`app/projection/visuals.py` classifies the signature explicitly and ships it as
`visual.signature`.

For `data_exfiltration`, `destination_rarity` and `destination_novel` are ranked
just behind the byte ratio deliberately. Volume alone false-positives on cloud
backup and video calls; volume to somewhere never contacted before is the real
signal, and it deserves to be visible near the top of the panel.

## Adding a class or a feature

1. Add the key to the relevant `_CLASS` dict in `thresholds.py` as a
   `ThresholdSpec` (has a bar) or `ContextSpec` (label/value only).
2. Pick `rank` so the most decisive feature sorts first. Lower is earlier.
3. If the feature needs a picture rather than a bar, add it to `_VISUAL_ONLY` in
   `evidence.py` and consume it in a builder in `visuals.py` — a 400-element
   series rendered as an evidence row pushes every real row off the panel.
4. Add a case to `tests/test_fusion.py::TestEvidenceProjection`.

# Layer 8 — AI Security Analyst

Explains alerts and narrates incidents in plain language, from the persisted
alert store, with **every claim traced to the evidence field it came from**.

```
backend  ──GET /api/v1/alerts──▶  retrieval  ──▶  grounding  ──▶  generation  ──▶  verification
         (read-only, allowlisted)   (no model)    (fact sheet)     (optional)      (reject ungrounded)
```

## The two things this layer must never do

**It must never influence detection.** It runs as its own process, on its own
port, and talks to the backend over the same public read-only API the dashboard
uses. `analyst/retrieval.py` exposes no method capable of issuing a POST, and
every path it may read is on a literal allowlist. Stop this process and nothing
upstream changes — which is the demonstration the Layered Build Plan (layer 8)
asks for.

**It must never say something no field supports.** The model is never shown an
alert. It is shown a numbered fact sheet built by `grounding.py`, where each
fact carries its source field, and it is asked to rephrase. Anything it returns
is then checked by `unsupported_numbers()`: a figure that appears nowhere in the
sheet causes the generated text to be **discarded**, not patched, and the
deterministic rendering is returned instead with the reason attached.

That is why the response carries `generated: true|false` and a `citations`
array. The panel shows which one you got.

## Run it

```bash
uvicorn analyst.main:app --port 8100
```

That is the whole setup. With no API key it uses the template provider: no
outbound connection, no credential, and it still answers every question from
stored evidence. To turn generation on, set two variables (see `.env.example`):

```bash
ANALYST_GEMINI_API_KEY=...
ANALYST_GEMINI_MODEL=gemini-2.5-flash-lite
```

> Set `ANALYST_GEMINI_MODEL` to a model your key can actually reach. The
> service does not hardcode a family, and `GET /api/v1/analyst/health` reports
> the configured id — so a wrong value surfaces before the demo rather than
> during it.

## Routes

| Route | Purpose |
|---|---|
| `POST /api/v1/analyst/explain` | `{"alert_id": "..."}` → plain-language explanation of one alert |
| `POST /api/v1/analyst/narrate` | `{"incident_id": "..."}` → kill-chain narrative for one incident |
| `POST /api/v1/analyst/ask` | `{"question": "..."}` → answer over the persisted alert history |
| `GET /api/v1/analyst/health` | provider, model, and whether the alert store is reachable |
| `GET /api/v1/analyst/constraints` | what this layer can and cannot reach — read this one out loud |

`/ask` is what the dashboard's chat dock calls. It is reachable from the
bottom-right of every view (`frontend/src/components/AnalystChat.tsx`), and
needs nothing selected — the subject is the corpus, not a row. The right-docked
`AnalystPanel` is the other surface: it explains whatever alert is selected,
without being asked. Both render answers through the same components, so a
badge or a citation means the same thing in either.

Every answer returns:

```jsonc
{
  "text": "...",
  "generated": true,            // false when rendered locally
  "provider": "gemini",
  "degraded_reason": null,      // why it fell back, when it did
  "citations": [                // one per claim, with its stored field
    { "text": "...", "source": "evidence.coefficient_of_variation", "value": 0.041 }
  ],
  "alert_ids": ["..."]
}
```

## Two sources, never blended

An answer draws on two things, and the panel keeps them visibly apart because
they are different kinds of claim.

**Measurement** comes from the alert store, cited to the field it came from —
`evidence.interval_cv`, `severity`, `GET /api/v1/alerts`. It is what this
network actually saw.

**Reference** comes from `knowledge.py`, cited as `knowledge base: <class>`. It
is what the threat *is*: why an attacker does it, how the detector recognises
it, which evidence fields carry the signal, the MITRE technique, what to
establish next, and — the line most consoles omit — what benign traffic has the
same shape. Retrieval cannot produce any of that, because none of it is a fact
about a row.

That split is why "what is DNS tunnelling" and "have we seen any" are one
answer rather than two features. It is also why the knowledge base contains not
one number:

> `unsupported_numbers()` builds the set of figures the model may state from
> every fact in the sheet. A reference line reading "beacons roughly every
> sixty seconds" would make 60 quotable as though something had measured it.
> Every figure in an answer comes from a stored field, so no figure goes in the
> reference text. `tests/test_knowledge.py` fails the build if one appears.

MITRE technique ids are the sole exception — identifiers, not measurements.

## The knowledge base needs no refresh

A threat is answerable as soon as it is in the store, because there is no index
between the two. Retrieval is a live `GET /api/v1/alerts` on every question, so
the corpus the analyst reads is the corpus as it stands at that moment.

Measured end to end: an alert POSTed to `/api/v1/alerts` was returned by
`/ask` **about one second later** — the backend's write-behind batch interval
(`DB_BATCH_INTERVAL_S`, default 0.5s), and nothing else. There is no embedding
job to run, no vector store to backfill, and no window during which a stored
threat is invisible to the analyst.

## Retrieval is structured, not embedded

`queryplan.py` parses a question into the filters the backend already indexes —
time window, host, threat class, severity — and the model never sees the corpus.
This is a deliberate choice, not a shortcut: the alert store is typed records
with indexed columns for exactly the three things every analyst question is
actually about. A vector index would add an embedding model, a backfill job, and
an approximate answer to a problem Postgres answers exactly.

The limit is real and is reported rather than hidden: a question phrased
entirely outside the schema falls back to a recent-alerts window, and the
response's `interpreted_as` field says so.

## "Does your LLM have network access?"

Have this answer ready; a judge will ask.

- **Default: no.** No key configured means no outbound socket. Explanations are
  rendered locally from stored evidence.
- **With Gemini configured: yes, and it is disclosed.** `GET
  /api/v1/analyst/constraints` names the single host (`generativelanguage.googleapis.com`),
  states the purpose, and says how to switch it off. There is exactly one
  outbound-capable module in this repository, `analyst/llm/gemini.py`, and the
  host is a module constant.
- **What is sent** is the derived fact sheet — the same text already visible on
  the dashboard. No packet capture, no payload, no raw flow record.
- **The ingest path is one-directional either way.** This process cannot reach
  the monitored network, and nothing it returns re-enters detection, scoring, or
  severity.

## Tests

```bash
python -m pytest analyst/tests -q
```

No network, no key, no model. The tests assert the properties that matter:
generation is never attempted on an empty fact sheet, an ungrounded figure is
rejected rather than shown, a provider failure degrades to the template answer
with the real evidence still in it, and a rule score is never described as a
probability.

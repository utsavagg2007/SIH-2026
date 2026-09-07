"""What a capture actually carried, so a degraded run says so out loud.

A detector that cannot fire because the observable it reads was never in the
input is indistinguishable, from the outside, from a detector that looked and
found nothing. Both produce silence. That difference matters more here than
almost anywhere else: "no C2 on this link" and "we could not have seen C2 on
this link" are opposite operational conclusions, and until now the runner
reported them identically.

The gap is real and reachable by ordinary use, not a hypothetical:

* ``ingestion/pipeline.py`` still defaults to the frozen ``legacy-m1d``
  feature profile. That profile emits no raw ``dns.query`` and no raw
  ``tls.ja3``, and flattens Zeek's ``S0`` to an encoding that decodes back to
  ``None``. A capture ingested without ``--feature-profile detector-v2``
  therefore reaches ``dga_domain`` and ``encrypted_malware`` with the exact
  fields those detectors are built on already stripped out.
* JA3/JA3S/JA4 exist in ``ssl.log`` only when Zeek ran with the qualified
  TLS-fingerprint runtime. Stock ``zeek/zeek:8.0.10`` writes an ``ssl.log``
  with no fingerprint columns at all, so the signature path stays dark no
  matter which feature profile ran afterwards.

Neither case is an error. Nothing is malformed, no record is skipped, and the
adapter's drift check stays quiet because every field it *expects* is present.
So this counts what arrived and reports, in terms of the detectors the
operator actually cares about, what this run was structurally unable to see.

Deliberately observational: it reads ``FlowEvent`` only, never the raw record,
so it makes no claim about which upstream profile produced the file - only
about what reached the detectors, which is the thing that determines whether a
silence means anything. Counts are per-flow, and every note names both the
detector affected and the concrete way to close the gap.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from ..schemas import FlowEvent

__all__ = ["ObservableCapability"]


@dataclass
class ObservableCapability:
    """Per-run tally of the raw observables detectors depend on."""

    #: Flows seen. Everything below is a subset of this.
    flows: int = 0
    #: Flows carrying no ``conn_state`` at all. Zeek always assigns one, so a
    #: non-zero count means the value was lost between Zeek and here.
    without_conn_state: int = 0
    #: Flows carrying a DNS block, and how many of those carried the query.
    dns_flows: int = 0
    dns_with_query: int = 0
    #: Flows carrying a TLS block, and how many carried each observable.
    tls_flows: int = 0
    tls_with_fingerprint: int = 0
    tls_with_server_name: int = 0

    def observe(self, event: FlowEvent) -> None:
        """Record one flow. Pure counting - the event is never modified."""
        self.flows += 1

        if event.conn_state is None:
            self.without_conn_state += 1

        dns = event.dns
        if dns is not None:
            self.dns_flows += 1
            if dns.query:
                self.dns_with_query += 1

        tls = event.tls
        if tls is not None:
            self.tls_flows += 1
            if tls.ja3 or tls.ja3s or tls.ja4:
                self.tls_with_fingerprint += 1
            if tls.server_name:
                self.tls_with_server_name += 1

    def watch(self, events: Iterable[FlowEvent]) -> Iterator[FlowEvent]:
        """Pass ``events`` straight through, counting as they go.

        A generator rather than a list: the runner is a streaming pipeline and
        this sits in the middle of it, so it must not be the one component
        that buffers a whole capture.
        """
        for event in events:
            self.observe(event)
            yield event

    def notes(self) -> list[str]:
        """Human-readable notes for whatever this run could not have seen.

        Empty when the capture carried everything - a fully-equipped run says
        nothing, so anything printed here is a real limitation on the result.
        """
        notes: list[str] = []

        if self.without_conn_state:
            notes.append(
                f"{self.without_conn_state} of {self.flows} flow(s) carried no "
                "conn_state; port_scan and ddos judge those on the "
                "responder-byte proxy instead, and Zeek's S0 (connection "
                "attempt, no reply) is indistinguishable from unknown. "
                "Re-run ingestion with --feature-profile detector-v2 to carry "
                "the raw state."
            )

        if self.dns_flows and not self.dns_with_query:
            notes.append(
                f"all {self.dns_flows} DNS flow(s) arrived without a raw "
                "dns.query, so dga_domain could not fire on any of them and "
                "dns_tunnelling lost its per-name signals. Re-run ingestion "
                "with --feature-profile detector-v2."
            )

        if self.tls_flows and not self.tls_with_fingerprint:
            notes.append(
                f"all {self.tls_flows} TLS flow(s) arrived without ja3/ja3s/ja4, "
                "so the encrypted_malware signature path could not fire "
                "(its SNI-metadata path is unaffected). Fingerprints need Zeek "
                "run with the qualified TLS-fingerprint runtime "
                "(ingestion/scripts/build_tls_fingerprint_runtime.sh) AND "
                "ingestion run with --feature-profile detector-v2."
            )

        if self.tls_flows and not self.tls_with_server_name:
            notes.append(
                f"all {self.tls_flows} TLS flow(s) arrived without a raw "
                "server_name, so the encrypted_malware SNI-metadata path had "
                "nothing to judge. Re-run ingestion with "
                "--feature-profile detector-v2."
            )

        return notes

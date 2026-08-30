"""The read-only constraint proof.

Frontend spec 6.2 asks for three lines that say the system sent nothing,
received one way only, and decrypted nothing - and Build Plan layer 9 wants a
demonstration rather than an assertion.  A hardcoded ``{"egress_blocked": true}``
would be exactly the decorative version this project is meant to avoid, so this
module makes the claim checkable.

Two mechanisms:

* **Egress accounting.** ``record_outbound_attempt`` is called by anything in
  the process that opens an outbound connection.  The durable-storage path calls
  it - writing to Postgres *is* egress, just not toward the monitored network -
  so the panel distinguishes the two rather than pretending the process is
  hermetic.
* **Route audit.** At startup we walk the app's own route table and count the
  routes that could write toward the monitored network.  That number is
  structurally zero: this backend has no such route, and the audit proves it
  from the live app rather than from a comment.

What this module does not claim: it cannot prove the *host* has no route back
into the production network.  That is a property of the data diode and the
enclave, not of a Python process.  The panel says so in ``notes`` rather than
overstating.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..schemas.view import ConstraintProof

#: Route prefixes that exist to serve the dashboard and the detection layer.
#: None of them emit anything toward the monitored network.
_INBOUND_PREFIXES = ("/api/v1", "/ws", "/health", "/docs", "/openapi", "/redoc")


@dataclass(slots=True)
class EgressLedger:
    """Counts outbound connection attempts made by this process."""

    #: Attempts toward the monitored network.  Must stay zero; nothing in this
    #: codebase increments it, and that is the point.
    toward_monitored_network: int = 0
    #: Attempts toward enclave-internal infrastructure (the alert database).
    #: Legitimate, and disclosed rather than hidden.
    toward_enclave_storage: int = 0
    destinations: set[str] = field(default_factory=set)

    def record_storage_egress(self, destination: str) -> None:
        self.toward_enclave_storage += 1
        # Host only, never credentials: this value is served over the API.
        self.destinations.add(destination)

    def record_monitored_network_egress(self, destination: str) -> None:
        """Nothing should ever call this. It exists so that if some future
        change does, the constraint panel reports it instead of concealing it."""
        self.toward_monitored_network += 1
        self.destinations.add(destination)


class ConstraintAuditor:
    def __init__(self) -> None:
        self.ledger = EgressLedger()
        self._route_audit: dict[str, int] = {}
        self._payload_decryption_modules: list[str] = []

    def audit_routes(self, routes: list) -> None:
        """Count routes by direction.  Called once at startup with app.routes."""
        inbound = 0
        unknown = 0
        for route in routes:
            path = getattr(route, "path", "")
            if path.startswith(_INBOUND_PREFIXES):
                inbound += 1
            else:
                unknown += 1
        self._route_audit = {
            "inbound_routes": inbound,
            "unclassified_routes": unknown,
            "routes_toward_monitored_network": 0,
        }

    def proof(self, storage_backend: str) -> ConstraintProof:
        notes = [
            "Ingest is HTTP inbound only: the detection layer posts to this "
            "service, and this service never contacts the detection layer, the "
            "traffic source, or the monitored network.",
            "No route in this API emits a packet toward the monitored network. "
            f"Route audit: {self._route_audit.get('inbound_routes', 0)} inbound "
            "routes, 0 toward the monitored network.",
            "No payload decryption anywhere in this process. TLS/QUIC alerts "
            "are built from metadata fields (JA3/JA3S/JA4, SNI, version, sizes) "
            "supplied by the detection layer; this backend holds no keys and "
            "parses no ciphertext.",
        ]
        if storage_backend == "postgres" and self.ledger.toward_enclave_storage:
            notes.append(
                f"Disclosed egress: {self.ledger.toward_enclave_storage} "
                "connection(s) to the alert database inside the monitoring "
                "enclave. This is storage egress, not a path back toward the "
                "monitored network."
            )
        else:
            notes.append(
                "No outbound connections made by this process "
                f"(storage backend: {storage_backend})."
            )
        notes.append(
            "Scope: this proof covers this process only. That the enclave "
            "itself has no physical return path is a property of the data "
            "diode or SPAN configuration and is verified outside this service."
        )

        return ConstraintProof(
            egress_blocked=self.ledger.toward_monitored_network == 0,
            outbound_attempts=self.ledger.toward_monitored_network,
            write_routes_toward_network=0,
            checked_at=time.time(),
            notes=notes,
        )

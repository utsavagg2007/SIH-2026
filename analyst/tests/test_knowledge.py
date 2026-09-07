"""The knowledge base is reference prose, so the tests guard the two ways
reference prose goes wrong: drifting from the frozen vocabulary it is keyed on,
and smuggling a number the model is then licensed to quote.
"""

from __future__ import annotations

import re

import pytest

from analyst.grounding import FactSheet, add_knowledge, unsupported_numbers
from analyst.knowledge import KNOWLEDGE, lookup

#: The frozen contract, from backend/app/schemas/enums.py::ThreatClass. Copied
#: rather than imported: the analyst runs as its own process and deliberately
#: does not import the backend, so this list is the seam between them and a
#: divergence should fail here loudly rather than degrade quietly at runtime.
THREAT_CLASSES = {
    "dga_domain",
    "dns_tunnelling",
    "c2_beaconing",
    "encrypted_malware",
    "ddos",
    "port_scan",
    "data_exfiltration",
}

#: MITRE technique ids are identifiers, not measurements, so their digits are
#: allowed in knowledge prose.
_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_NUMBER = re.compile(r"\d+(?:\.\d+)?")


def _measurements(text: str) -> list[str]:
    """Figures in *text* that the verifier would treat as claims.

    Two kinds of digit are excluded, because neither can be mistaken for
    something a detector measured:

    * MITRE technique ids, stripped before scanning;
    * anything at or below ten, which ``unsupported_numbers`` already ignores
      as an ordinal or small count. That exemption is what lets the prose write
      "a JA3 or JA4 fingerprint" and name evidence keys like ``ja3_rarity`` -
      those are format and field names, and the 3 and the 4 in them are not
      figures a model could pass off as a reading.

    What is left is exactly the set that would be newly quotable because this
    file said so, and that set must be empty.
    """
    return [
        token
        for token in _NUMBER.findall(_MITRE.sub("", text))
        if float(token) > 10 or float(token) != int(float(token))
    ]


def test_every_frozen_threat_class_has_an_entry():
    assert set(KNOWLEDGE) == THREAT_CLASSES


@pytest.mark.parametrize("threat_class", sorted(THREAT_CLASSES))
def test_prose_carries_no_measurements(threat_class):
    """No threshold, rate, duration or count anywhere in the reference text.

    This is the rule that keeps the verifier meaningful. ``FactSheet.numbers()``
    builds the set of figures the model is permitted to state from every fact in
    the sheet, so a knowledge line reading "beacons every sixty seconds" would
    make 60 quotable as though a detector had measured it. Every number in an
    answer has to come from a stored field, so no number goes in here.
    """
    entry = KNOWLEDGE[threat_class]
    prose = " ".join(
        (entry.summary, entry.intent, entry.detection, entry.investigate, entry.benign_lookalike)
    )
    assert _measurements(prose) == [], (
        f"{threat_class} knowledge prose quotes a figure; write it in words or "
        "let it come from a stored field"
    )


@pytest.mark.parametrize("threat_class", sorted(THREAT_CLASSES))
def test_knowledge_facts_license_no_new_figures(threat_class):
    """The end-to-end version of the rule above, through the real code path.

    A sheet built from knowledge alone must permit no figure except the MITRE
    ids it states - so a model answering a definition question cannot quote a
    measurement and have it accepted.
    """
    sheet = FactSheet(subject=threat_class, kind="corpus")
    assert add_knowledge(sheet, threat_class) is True

    # Anything the verifier would accept purely because this file said so.
    newly_quotable = {
        token for token in sheet.numbers() if _measurements(token)
    } - {
        part
        for identifier in KNOWLEDGE[threat_class].mitre
        for part in _NUMBER.findall(identifier)
    }
    assert newly_quotable == set()

    # And the verifier still rejects an invented figure against that sheet.
    assert unsupported_numbers("The interval was 62.5 seconds.", sheet) == ["62.5"]


@pytest.mark.parametrize("threat_class", sorted(THREAT_CLASSES))
def test_every_claim_is_sourced_to_the_knowledge_base(threat_class):
    """Never to an evidence field. The panel renders the source beside each
    claim, and background must not be able to pass itself off as measurement."""
    sheet = FactSheet(subject=threat_class, kind="corpus")
    add_knowledge(sheet, threat_class)
    assert {f.source for f in sheet.facts} == {f"knowledge base: {threat_class}"}


def test_unknown_class_adds_nothing():
    """A class we have no entry for is answered from alerts alone, not guessed."""
    sheet = FactSheet(subject="x", kind="corpus")
    assert add_knowledge(sheet, "cryptomining") is False
    assert add_knowledge(sheet, None) is False
    assert sheet.is_empty


def test_evidence_fields_are_named_and_ordered():
    """Each entry points at real keys. The names are what an analyst types into
    the evidence panel next, so an empty list would make the advice unusable."""
    for threat_class, entry in KNOWLEDGE.items():
        assert entry.evidence_fields, threat_class
        assert entry.mitre, threat_class
        assert all(re.fullmatch(r"[a-z0-9_]+", f) for f in entry.evidence_fields), threat_class
        assert all(_MITRE.fullmatch(m) for m in entry.mitre), threat_class


def test_lookup_matches_the_table():
    assert lookup("c2_beaconing") is KNOWLEDGE["c2_beaconing"]
    assert lookup("nonsense") is None
    assert lookup(None) is None

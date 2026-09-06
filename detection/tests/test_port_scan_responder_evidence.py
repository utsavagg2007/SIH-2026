"""Responder-engagement gate: the three ways it used to silence a real scan.

The existing port_scan tests exercise ``S0`` and ``SF`` and a scan-only
window, so all three of these passed straight through them:

* a window whose states are all ``OTH`` (or unrecognised, or empty) reported
  full ``conn_state`` coverage and a zero incomplete share - "the responder
  answered everything" - and suppressed a no-reply scan that the byte proxy
  would have caught outright;
* the byte proxy divided by the whole per-source window, so ordinary answered
  browsing sharing that window diluted the reading until a real scan fell
  below the gate;
* **and the choice of branch was itself a per-flow reading.** Under the frozen
  ``legacy-m1d`` profile a sweep arrives unlabelled (``S0`` flattens to
  ``None``) while ordinary browsing arrives ``SF``, so enough browsing pushed
  per-flow coverage over ``min_conn_state_coverage`` and handed the verdict to
  a branch holding no evidence about the sweep at all - which then read its
  0.0 incomplete share as "the responder answered". Fixing the first two left
  this one: the gate had stopped mismeasuring, but was still asking the wrong
  half of the window.

The invariant all three halves defend: **evidence may only suppress a scan
when it is evidence about the endpoints being scanned.** Traffic to unrelated
endpoints has no vote, whether it votes with bytes, with states, or by
deciding which of the two gets read.
"""

from __future__ import annotations

import pytest

from detection_core import PortScanConfig, PortScanDetector
from detection_core.aggregators import (
    CLASSIFIED_CONN_STATES,
    COMPLETE_CONN_STATES,
    INCOMPLETE_CONN_STATES,
)

from .conftest import make_flow

SCANNER = "10.0.0.66"
VICTIM = "10.0.0.80"
CDN = "93.184.216.34"


@pytest.fixture
def config() -> PortScanConfig:
    return PortScanConfig(
        window_seconds=60.0,
        min_unique_ports=15,
        min_unique_hosts=20,
        cooldown_seconds=300.0,
    )


def probe(ts: float, port: int, *, dst: str = VICTIM, conn_state=None):
    """One unanswered connection attempt - the shape a scan is made of."""
    return make_flow(
        flow_id=f"probe-{dst}-{port}-{ts}",
        timestamp=ts,
        src_ip=SCANNER,
        dst_ip=dst,
        dst_port=port,
        orig_bytes=40,
        resp_bytes=0,
        orig_pkts=1,
        resp_pkts=0,
        conn_state=conn_state,
    )


def answered(ts: float, port: int, *, dst: str = CDN, conn_state=None):
    """One ordinary answered request - a page, a DNS reply, a handshake."""
    return make_flow(
        flow_id=f"answered-{dst}-{port}-{ts}",
        timestamp=ts,
        src_ip=SCANNER,
        dst_ip=dst,
        dst_port=port,
        orig_bytes=350,
        resp_bytes=8_000,
        orig_pkts=5,
        resp_pkts=9,
        conn_state=conn_state,
    )


def vertical_sweep(state=None, *, count: int = 30, start: float = 1_000.0):
    """``count`` distinct service ports on one host, none of them answered."""
    return [probe(start + i * 0.1, 20 + i, conn_state=state) for i in range(count)]


def run(detector: PortScanDetector, flows):
    alerts = []
    for flow in sorted(flows, key=lambda f: f.timestamp):
        alerts.extend(detector.process(flow))
    return alerts


# --------------------------------------------------------------------------
# 1. Unclassified states must not manufacture coverage
# --------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["OTH", "ZZ", "", "   ", "s0", "unknown"])
def test_an_unclassified_state_window_still_alerts(config, state):
    """OTH / unrecognised / blank is the ABSENCE of a verdict, not an answer.

    Each of these used to report coverage 1.0 and incomplete 0.0, which took
    the conn_state branch and silenced the scan. They must instead read as
    uncovered and fall through to the byte proxy, which sees no responder
    bytes at all and passes.
    """
    detector = PortScanDetector(config)
    alerts = run(detector, vertical_sweep(state))

    window = detector._windows.get(SCANNER)
    assert window.conn_state_coverage() == 0.0, (
        f"{state!r} is not a classified state and must not count as covered"
    )
    assert alerts, f"a no-reply scan reported as {state!r} went silent"


def test_a_classified_state_window_is_still_trusted(config):
    """The fix must not cost us the real signal: S0 still drives the gate."""
    detector = PortScanDetector(config)
    alerts = run(detector, vertical_sweep("S0"))

    window = detector._windows.get(SCANNER)
    assert window.conn_state_coverage() == 1.0
    assert window.incomplete_fraction() == 1.0
    assert alerts
    assert alerts[0].evidence["responder_evidence"] == "conn_state"


def test_no_unclassified_state_silences_what_the_proxy_catches(config):
    """The load-bearing invariant, stated over every state that is not a verdict.

    For a no-reply scan, no *unclassified* ``conn_state`` may produce fewer
    alerts than the same scan carrying no state at all - because none of them
    carries information the proxy does not already have.

    A window of genuine ``COMPLETE_CONN_STATES`` is deliberately excluded:
    there, ingestion is asserting the responder did complete every exchange,
    and suppressing on that is the whole point of trusting ``conn_state`` over
    the proxy. That case is pinned by
    ``test_a_completed_conn_state_window_is_still_suppressed``.
    """
    baseline = run(PortScanDetector(config), vertical_sweep(None))
    assert baseline, "the byte proxy must catch an unanswered sweep"

    unclassified = ["OTH", "", "   ", "ZZ", "RSTOS0 ", "s0", "unknown", None]
    for state in sorted(INCOMPLETE_CONN_STATES) + unclassified:
        alerts = run(PortScanDetector(config), vertical_sweep(state))
        assert alerts, f"conn_state={state!r} silenced a scan the proxy catches"


def test_mixed_coverage_below_the_floor_falls_to_the_proxy(config):
    """Half OTH, half absent: still nothing classified, so still the proxy."""
    detector = PortScanDetector(config)
    flows = vertical_sweep(None, count=15)
    flows += [
        probe(1_000.0 + (15 + i) * 0.1, 35 + i, conn_state="OTH") for i in range(15)
    ]
    alerts = run(detector, flows)

    window = detector._windows.get(SCANNER)
    assert window.conn_state_coverage() == 0.0
    assert alerts


# --------------------------------------------------------------------------
# 2. Answered browsing must not dilute a scan out of the window
# --------------------------------------------------------------------------


@pytest.mark.parametrize("browsing_flows", [0, 4, 8, 16, 40, 200])
def test_browsing_in_the_same_window_does_not_suppress_a_scan(
    config, browsing_flows
):
    """A source that browses AND scans is still a source that scans.

    Eight answered browsing flows used to be enough to push a thirty-port
    sweep past ``max_established_fraction`` and silence it. Browsing is a
    couple of endpoints carrying many flows; the gate now measures endpoints,
    so volume on those endpoints has no leverage over the verdict.
    """
    detector = PortScanDetector(config)
    browse = [
        answered(1_000.0 + i * 0.1 + 0.05, 443 if i % 2 else 80)
        for i in range(browsing_flows)
    ]
    alerts = run(detector, browse + vertical_sweep(None))

    assert alerts, f"{browsing_flows} browsing flows suppressed a real scan"


def test_browse_then_scan_in_sequence_still_alerts(config):
    """The mixed window, in the order it actually happens: browse, then scan."""
    detector = PortScanDetector(config)
    browse = [answered(1_000.0 + i * 0.5, 443 if i % 2 else 80) for i in range(12)]
    scan = [probe(1_010.0 + i * 0.1, 20 + i) for i in range(30)]
    alerts = run(detector, browse + scan)

    assert alerts
    # The alert fires on the flow that crosses the threshold, part-way through
    # the sweep, so the window it reports is the window as it stood then.
    evidence = alerts[0].evidence
    assert evidence["responder_evidence"] == "resp_bytes"
    # The browsing endpoints are present and answered - they are simply not
    # allowed to outvote the unanswered ones.
    assert evidence["established_endpoints"] == 2
    # Browsing's own two ports (80, 443) count toward the port threshold too,
    # so the window crosses it holding 13 swept ports plus those two.
    assert evidence["unique_endpoints"] == config.min_unique_ports
    assert evidence["endpoint_established_fraction"] == round(
        2 / config.min_unique_ports, 4
    )
    # Well under the ceiling, where the per-flow reading would have been
    # 12 answered of 27 - 0.44, four times over it.
    assert (
        evidence["endpoint_established_fraction"]
        <= config.max_established_fraction
    )
    assert evidence["established_fraction"] > config.max_established_fraction


def test_horizontal_sweep_survives_one_host_answering(config):
    """A subnet sweep where a single host happens to serve is still a sweep."""
    detector = PortScanDetector(config)
    sweep = [probe(1_000.0 + i * 0.1, 445, dst=f"10.0.5.{i}") for i in range(30)]
    sweep.append(answered(1_003.5, 445, dst="10.0.5.99"))
    alerts = run(detector, sweep)

    assert alerts
    assert alerts[0].evidence["scan_type"] in {"horizontal", "combined"}


# --------------------------------------------------------------------------
# 3. The suppression this gate was built for must survive all of the above
# --------------------------------------------------------------------------


def test_answered_browsing_alone_is_still_suppressed(config):
    """The false-positive shape the gate exists to kill, still killed.

    A source fanning out across many hosts on 443 with everything answered is
    a browser, not a scanner. Endpoint scoping must not reopen this: every
    endpoint it touched served it, so the fraction is 1.0.
    """
    detector = PortScanDetector(config)
    browsing = [
        answered(1_000.0 + i * 0.1, 443, dst=f"93.184.216.{i}") for i in range(40)
    ]
    alerts = run(detector, browsing)

    window = detector._windows.get(SCANNER)
    assert window.endpoint_established_fraction() == 1.0
    assert not alerts, "answered browsing must stay suppressed"


def test_a_completed_conn_state_window_is_still_suppressed(config):
    """The same suppression on the conn_state path: SF everywhere is traffic."""
    detector = PortScanDetector(config)
    flows = [
        answered(1_000.0 + i * 0.1, 443, dst=f"93.184.216.{i}", conn_state="SF")
        for i in range(40)
    ]
    alerts = run(detector, flows)

    window = detector._windows.get(SCANNER)
    assert window.conn_state_coverage() == 1.0
    assert window.incomplete_fraction() == 0.0
    assert not alerts


def test_the_state_sets_partition_cleanly():
    """COMPLETE and INCOMPLETE are disjoint, and OTH belongs to neither."""
    assert not (COMPLETE_CONN_STATES & INCOMPLETE_CONN_STATES)
    assert CLASSIFIED_CONN_STATES == COMPLETE_CONN_STATES | INCOMPLETE_CONN_STATES
    assert "OTH" not in CLASSIFIED_CONN_STATES
    assert "S0" in INCOMPLETE_CONN_STATES
    assert "SF" in COMPLETE_CONN_STATES


# --------------------------------------------------------------------------
# 4. A classified state on unrelated endpoints must not decide the verdict
# --------------------------------------------------------------------------
#
# The residual case, and the reason `min_conn_state_coverage` is now read per
# endpoint. Every scan below is *unlabelled* - the frozen `legacy-m1d` shape,
# where `encode_conn_state` has no `S0` arm - while the browsing beside it is
# `SF`. The browsing is the only thing in the window carrying a state, so on a
# per-flow reading it alone chose the branch, and the branch it chose could
# only ever see its own completed exchanges.


def sf_browsing(count: int, *, start: float = 1_000.0, step: float = 0.05):
    """``count`` ordinary answered flows, labelled the way Zeek labels them.

    Two endpoints (the CDN on 80 and on 443) carrying however many flows -
    which is the shape of real browsing, and the shape that used to be able
    to outvote a sweep purely by being numerous.
    """
    return [
        answered(start + i * step, 443 if i % 2 else 80, conn_state="SF")
        for i in range(count)
    ]


def unlabelled_sweep(count: int = 30, *, start: float = 1_010.0):
    """A vertical sweep as ``legacy-m1d`` delivers it: no state at all."""
    return [probe(start + i * 0.1, 20 + i) for i in range(count)]


@pytest.mark.parametrize("browsing_flows", [30, 40, 60, 100, 200, 500])
def test_sf_browsing_cannot_route_an_unlabelled_scan_to_the_conn_state_branch(
    config, browsing_flows
):
    """The reproduction, at every volume that used to silence it.

    Browsing first, then the sweep - the ordinary sequence, and the one where
    the browsing has fully accumulated before the sweep crosses its threshold.
    Below 30 browsing flows this alerted anyway; at and above it the detector
    went completely silent, and stayed silent however large the scan grew.
    """
    detector = PortScanDetector(config)
    flows = sf_browsing(browsing_flows) + unlabelled_sweep()
    alerts = run(detector, flows)

    assert alerts, f"{browsing_flows} SF browsing flows silenced a 30-port sweep"


def test_the_reproduced_window_is_exactly_the_one_that_used_to_go_silent(config):
    """Pin the diagnosis, not just the symptom.

    Every number that drove the old suppression is asserted here, so if a
    future change restores the per-flow reading this fails with the reason
    rather than with a bare "no alerts".
    """
    detector = PortScanDetector(config)
    alerts = run(detector, sf_browsing(40) + unlabelled_sweep())
    window = detector._windows.get(SCANNER)

    # The per-flow reading: over the floor, and reporting a fully answered
    # window - which is what used to take the branch and then suppress.
    assert window.conn_state_coverage() >= config.min_conn_state_coverage
    assert window.conn_state_coverage() == pytest.approx(40 / 70, abs=1e-4)
    assert window.incomplete_fraction() == 0.0

    # The endpoint reading: two labelled endpoints out of thirty-two, which is
    # nowhere near the floor, so the proxy decides.
    assert window.endpoint_conn_state_coverage() == pytest.approx(2 / 32)
    assert window.endpoint_conn_state_coverage() < config.min_conn_state_coverage

    # And the proxy passes it - which it always would have, had it been asked.
    assert window.endpoint_established_fraction() == pytest.approx(2 / 32)
    assert window.endpoint_established_fraction() <= config.max_established_fraction

    assert alerts
    assert alerts[0].evidence["responder_evidence"] == "resp_bytes"


@pytest.mark.parametrize("browsing_flows", [40, 100])
@pytest.mark.parametrize("ordering", ["browse-first", "interleaved", "scan-first"])
def test_every_ordering_of_the_mixed_window_still_alerts(
    config, browsing_flows, ordering
):
    """Order must not be what saves us.

    Interleaved and scan-first used to alert, but only by luck: the sweep
    crossed its port threshold before enough browsing had accumulated to flip
    the branch. That is a race with traffic volume, not a property - and
    browse-first, the ordinary sequence, lost it outright.
    """
    if ordering == "browse-first":
        flows = sf_browsing(browsing_flows) + unlabelled_sweep()
    elif ordering == "interleaved":
        flows = sf_browsing(browsing_flows, start=1_000.05, step=0.1)
        flows += unlabelled_sweep(start=1_000.0)
    else:
        flows = unlabelled_sweep(start=1_000.0)
        flows += sf_browsing(browsing_flows, start=1_010.0)

    alerts = run(PortScanDetector(config), flows)
    assert alerts, f"{ordering} with {browsing_flows} browsing flows went silent"


def test_an_s0_scan_beside_sf_browsing_takes_the_conn_state_branch(config):
    """When the sweep *is* labelled, the branch runs and still catches it.

    This is the case endpoint scoping must not cost us: the states are real,
    they cover the window, and they say the swept endpoints refused. Thirty
    refusing endpoints against two that served is 0.9375 - so the same
    browsing that used to suppress the scan now cannot even dent it.
    """
    detector = PortScanDetector(config)
    flows = sf_browsing(40) + [
        probe(1_010.0 + i * 0.1, 20 + i, conn_state="S0") for i in range(30)
    ]
    alerts = run(detector, flows)
    window = detector._windows.get(SCANNER)

    assert window.endpoint_conn_state_coverage() == 1.0
    assert window.endpoint_incomplete_fraction() == pytest.approx(30 / 32)
    assert alerts
    assert alerts[0].evidence["responder_evidence"] == "conn_state"


def test_a_stateless_scan_beside_stateless_answered_browsing_still_alerts(config):
    """Neither side labelled: nothing can reach the branch, proxy decides."""
    detector = PortScanDetector(config)
    browse = [answered(1_000.0 + i * 0.05, 443 if i % 2 else 80) for i in range(40)]
    alerts = run(detector, browse + unlabelled_sweep())
    window = detector._windows.get(SCANNER)

    assert window.endpoint_conn_state_coverage() == 0.0
    assert alerts


def test_an_oth_sweep_beside_sf_browsing_still_alerts(config):
    """The two defects composed: unclassified sweep, labelled browsing.

    ``OTH`` is not a verdict, so those thirty endpoints stay uncovered and the
    two ``SF`` ones cannot carry the window to the branch on their own.
    """
    detector = PortScanDetector(config)
    flows = sf_browsing(40) + [
        probe(1_010.0 + i * 0.1, 20 + i, conn_state="OTH") for i in range(30)
    ]
    alerts = run(detector, flows)
    window = detector._windows.get(SCANNER)

    assert window.endpoint_conn_state_coverage() == pytest.approx(2 / 32)
    assert alerts


def test_a_horizontal_sweep_survives_sf_browsing_in_the_same_window(config):
    """The same defect on the horizontal signal, which shares the gate.

    Thirty hosts on 445, unlabelled, beside browsing on 80 and 443. The swept
    port is not one the browsing touches, so the fan-out is the sweep's alone -
    and the browsing's states must not decide its fate either.
    """
    detector = PortScanDetector(config)
    sweep = [probe(1_010.0 + i * 0.1, 445, dst=f"10.0.5.{i}") for i in range(30)]
    alerts = run(detector, sf_browsing(40) + sweep)

    assert alerts
    assert alerts[0].evidence["scan_type"] == "horizontal"
    assert alerts[0].evidence["horizontal_dst_port"] == 445


# --------------------------------------------------------------------------
# 5. Endpoint scoping must not weaken responder suppression
# --------------------------------------------------------------------------


def test_an_answered_labelled_vertical_fan_out_is_still_suppressed(config):
    """The control that matters most: a *labelled, answered* vertical shape.

    Thirty service ports on one host, every one of them ``SF``. This is the
    branch doing its job - ingestion is asserting these exchanges completed,
    the endpoints carrying that assertion are the endpoints being judged, and
    suppressing on it is the entire reason the branch is preferred to the
    proxy. Endpoint scoping must not reopen it.
    """
    detector = PortScanDetector(config)
    flows = [
        answered(1_000.0 + i * 0.1, 20 + i, dst=VICTIM, conn_state="SF")
        for i in range(30)
    ]
    alerts = run(detector, flows)
    window = detector._windows.get(SCANNER)

    assert window.endpoint_conn_state_coverage() == 1.0
    assert window.endpoint_incomplete_fraction() == 0.0
    assert not alerts, "a fully answered labelled window must stay suppressed"


def test_an_answered_labelled_horizontal_fan_out_is_still_suppressed(config):
    """The same control on the horizontal signal: forty hosts on 443, all SF."""
    detector = PortScanDetector(config)
    flows = [
        answered(1_000.0 + i * 0.1, 443, dst=f"93.184.216.{i}", conn_state="SF")
        for i in range(40)
    ]
    alerts = run(detector, flows)
    window = detector._windows.get(SCANNER)

    assert window.endpoint_conn_state_coverage() == 1.0
    assert window.endpoint_incomplete_fraction() == 0.0
    assert not alerts


def test_answered_ephemeral_fan_out_is_still_suppressed(config):
    """Benign ephemeral fan-out - the reply side of ordinary client traffic."""
    detector = PortScanDetector(config)
    flows = [
        answered(1_000.0 + i * 0.1, 50_000 + i, dst=VICTIM, conn_state="SF")
        for i in range(40)
    ]
    assert not run(detector, flows)


def test_an_endpoint_that_ever_completed_is_not_counted_incomplete(config):
    """A refused attempt then a served one is an endpoint that engaged.

    The conservative reading, spelled out: ``endpoint_incomplete_fraction``
    can only ever be lowered by a completed exchange, never raised by a
    refused one, so it cannot manufacture a scan out of a served endpoint.
    """
    detector = PortScanDetector(config)
    flows = []
    for i in range(30):
        port = 20 + i
        flows.append(probe(1_000.0 + i * 0.1, port, dst=VICTIM, conn_state="REJ"))
        flows.append(answered(1_000.05 + i * 0.1, port, dst=VICTIM, conn_state="SF"))
    run(detector, flows)
    window = detector._windows.get(SCANNER)

    assert window.endpoint_conn_state_coverage() == 1.0
    assert window.endpoint_incomplete_fraction() == 0.0
    # The per-flow reading disagrees - half those flows were refused - which
    # is exactly the difference endpoint scoping is making.
    assert window.incomplete_fraction() == 0.5

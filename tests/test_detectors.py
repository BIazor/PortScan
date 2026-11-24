"""End-to-end detection tests over labelled synthetic Nmap captures."""

from __future__ import annotations

import pytest

from portscan.cli import analyze_capture
from portscan.synth import SCENARIOS, write_scenario


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_scenario_reports_exactly_the_expected_techniques(name, tmp_path):
    """Each labelled capture must produce its technique and nothing else."""
    title, expected, _ = SCENARIOS[name]
    path = tmp_path / f"{name}.pcap"
    write_scenario(name, path)

    report = analyze_capture(path)

    detected = {finding.technique for finding in report.findings}
    assert detected == set(expected), (
        f"{title}: expected {sorted(expected)}, got "
        f"{sorted(detected)} ({[f.title for f in report.findings]})"
    )
    assert report.packets > 0


def test_syn_scan_evidence_is_specific(tmp_path):
    path = tmp_path / "syn.pcap"
    write_scenario("syn_scan", path)

    report = analyze_capture(path)

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.technique == "syn"
    assert finding.scanner == "10.10.0.99"
    assert finding.target == "10.10.0.50"
    assert finding.ports == 300
    assert finding.confidence >= 0.9
    assert any("handshake" in line for line in finding.evidence)


def test_benign_traffic_produces_no_findings(tmp_path):
    for name in ("benign_web", "benign_dns"):
        path = tmp_path / f"{name}.pcap"
        write_scenario(name, path)
        report = analyze_capture(path)
        assert report.findings == [], f"{name} produced {report.findings}"


def test_threshold_is_configurable(tmp_path):
    from portscan.detectors import DetectionConfig

    path = tmp_path / "syn.pcap"
    write_scenario("syn_scan", path)

    # Requiring more ports than were scanned must silence the detector.
    report = analyze_capture(path, detection=DetectionConfig(min_ports=500))
    assert report.findings == []


def test_session_gap_splits_bursts(tmp_path):
    path = tmp_path / "syn.pcap"
    write_scenario("syn_scan", path)

    report = analyze_capture(path, session_gap=0.0)
    # A 0s gap turns every probe into its own session, so no fan-out is seen.
    assert report.findings == []

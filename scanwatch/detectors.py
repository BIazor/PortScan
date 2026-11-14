"""Classification of scan sessions into Nmap reconnaissance techniques.

Each rule looks at one session (one scanner -> one target burst) and asks a
question that is specific to a Nmap technique: *were there bare SYNs that never
completed a handshake?*, *did ports complete a handshake and get closed without
data?*, *were there ACK-only segments to untouched ports?* and so on.
Confidence blends how much evidence there is (volume) with how pure it is
(share of probes that match the signature).
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, PortProbe, ScanSession, flags_to_text
from .tracker import DISCOVERY_PORTS, Analysis

TECHNIQUES: dict[str, tuple[str, str]] = {
    "syn": (
        "TCP SYN scan (nmap -sS)",
        "half-open port scan: bare SYNs that never complete a handshake",
    ),
    "connect": (
        "TCP connect scan (nmap -sT)",
        "full handshakes opened and closed without data",
    ),
    "fin": ("TCP FIN scan (nmap -sF)", "bare FIN segments to closed ports"),
    "xmas": ("TCP XMAS scan (nmap -sX)", "FIN+PSH+URG 'Christmas tree' probes"),
    "null": ("TCP NULL scan (nmap -sN)", "TCP segments with no flags set"),
    "ack": ("TCP ACK scan (nmap -sA)", "ACK-only probes used for firewall mapping"),
    "maimon": ("TCP Maimon scan (nmap -sM)", "FIN+ACK probes"),
    "udp": ("UDP scan (nmap -sU)", "UDP datagrams to many ports"),
    "version": (
        "Service/version detection (nmap -sV)",
        "application data sent after the handshake to fingerprint services",
    ),
    "os_fingerprint": (
        "OS fingerprint probes (nmap -O)",
        "illegal TCP flag combinations used to fingerprint the stack",
    ),
    "host_sweep": ("Host discovery sweep (nmap -sn)", "ICMP discovery probes to many hosts"),
    "port_sweep": ("Horizontal port sweep", "one port probed across many hosts"),
}


@dataclass
class DetectionConfig:
    """Thresholds for the detection rules.

    ``min_ports`` is the fan-out that separates a scan from ordinary client
    behaviour; the remaining knobs exist because each technique exposes a
    different amount of evidence in a capture.
    """

    min_ports: int = 15
    min_hosts: int = 5
    min_connect_ports: int = 3
    min_version_ports: int = 3
    # A handful of datagrams to consecutive ports is routine service discovery
    # (mDNS/SSDP-style chatter), so a UDP scan needs a wide fan-out. Real -sU
    # runs touch hundreds of ports; the lab capture shows 60 after ICMP rate
    # limiting, so 25 separates the two cleanly.
    min_udp_ports: int = 25
    min_anomaly_probes: int = 1


def detect(analysis: Analysis, config: DetectionConfig | None = None) -> list[Finding]:
    """Run every rule over the tracked sessions and return merged findings."""
    cfg = config or DetectionConfig()
    findings: list[Finding] = []
    for session in analysis.sessions:
        findings.extend(_detect_session(session, cfg))
    findings.extend(_detect_sweeps(analysis, cfg))
    return _merge(findings)


# --------------------------------------------------------------------- rules


def _detect_session(session: ScanSession, cfg: DetectionConfig) -> list[Finding]:
    tcp = session.tcp_probes
    findings: list[Finding] = []

    if tcp:
        findings.extend(_detect_tcp_scan(session, tcp, cfg))
        findings.extend(_detect_tcp_anomalies(session, tcp, cfg))

    udp = session.udp_probes
    if len(udp) >= cfg.min_udp_ports:
        unreachable = sum(1 for probe in udp if probe.icmp_unreachable)
        evidence = [
            f"{len(udp)} UDP datagrams sent to distinct ports in {session.duration:.2f}s",
        ]
        if unreachable:
            evidence.append(
                f"{unreachable} port(s) answered ICMP port-unreachable (closed)"
            )
        else:
            evidence.append("no ICMP unreachable replies observed (filtered or local target)")
        evidence.append(f"ports: {_ports_text(probe.port for probe in udp)}")
        findings.append(
            _finding(
                session,
                "udp",
                ports=len(udp),
                confidence=_confidence(len(udp), len(udp), cfg, unreachable / len(udp)),
                evidence=evidence,
            )
        )

    return findings


def _detect_tcp_scan(
    session: ScanSession, tcp: list[PortProbe], cfg: DetectionConfig
) -> list[Finding]:
    total = len(tcp)
    syn = [probe for probe in tcp if "syn" in probe.kinds]
    handshaked = [probe for probe in tcp if probe.completions > 0]
    silent_handshakes = [
        probe for probe in handshaked if probe.payload == 0
    ]
    version_ports = [
        probe
        for probe in tcp
        if probe.completions > 0 and probe.payload_segments >= 1
    ]
    findings: list[Finding] = []

    # ``-sT`` also emits bare SYNs to closed ports, so completed handshakes are
    # the evidence that separates a connect scan from a half-open SYN scan.
    if len(silent_handshakes) >= cfg.min_connect_ports:
        findings.append(
            _finding(
                session,
                "connect",
                ports=len(silent_handshakes),
                confidence=_confidence(
                    len(silent_handshakes),
                    len(handshaked),
                    cfg,
                    1.0,
                    full_scale=3 * cfg.min_connect_ports,
                ),
                evidence=[
                    f"{len(silent_handshakes)} of {total} probed ports completed a full "
                    "3-way handshake and were closed without sending data",
                    f"listening ports: {_ports(silent_handshakes)}",
                ],
            )
        )
    elif len(syn) >= cfg.min_ports and len(syn) / total >= 0.8:
        responded = sum(1 for probe in syn if probe.responded)
        evidence = [
            f"{len(syn)}/{total} TCP probes carried a bare SYN and never completed a "
            "handshake",
            f"{responded}/{len(syn)} probes drew a response "
            f"({sum(probe.synack for probe in syn)} SYN+ACK, "
            f"{sum(probe.rst_from_target for probe in syn)} RST)",
        ]
        if not responded:
            evidence.append("no responses at all - scan may be filtered or captured one-way")
               
        windows = {window for probe in syn for window in probe.windows}
        if len(windows) == 1:
            evidence.append(
                f"constant TCP window {windows.pop()} on every SYN (Nmap's default)"
            )
        if session.duration > 0:
            evidence.append(
                f"fan-out rate {len(syn) / session.duration:.0f} probes/s "
                f"over {session.duration:.2f}s"
            )
        findings.append(
            _finding(
                session,
                "syn",
                ports=len(syn),
                confidence=_confidence(len(syn), total, cfg, responded / len(syn)),
                evidence=evidence,
            )
        )

    if len(version_ports) >= cfg.min_version_ports:
        findings.append(
            _finding(
                session,
                "version",
                ports=len(version_ports),
                confidence=_confidence(
                    len(version_ports),
                    len(handshaked),
                    cfg,
                    1.0,
                    full_scale=3 * cfg.min_version_ports,
                ),
                evidence=[
                    f"{len(version_ports)} ports received application data after a "
                    "completed handshake",
                    f"{sum(probe.payload for probe in version_ports)} bytes in "
                    f"{sum(probe.payload_segments for probe in version_ports)} "
                    "probe segment(s)",
                    f"ports: {_ports(version_ports)}",
                ],
            )
        )

    return findings


def _detect_tcp_anomalies(
    session: ScanSession, tcp: list[PortProbe], cfg: DetectionConfig
) -> list[Finding]:
    findings: list[Finding] = []

    for kind, technique in (
        ("xmas", "xmas"),
        ("null", "null"),
        ("fin", "fin"),
        ("maimon", "maimon"),
        ("ack", "ack"),
    ):
        probes = [probe for probe in tcp if kind in probe.kinds]
        if len(probes) < cfg.min_ports:
            continue

        responded = sum(1 for probe in probes if probe.responded)
        evidence = [_flag_evidence(technique, probes)]
        if responded:
            evidence.append(
                f"{responded}/{len(probes)} probes answered (RST from closed ports)"
            )
        else:
            evidence.append("no responses observed (filtered or local target)")
        evidence.append(f"ports: {_ports(probes)}")
        findings.append(
            _finding(
                session,
                technique,
                ports=len(probes),
                confidence=_confidence(
                    len(probes), len(tcp), cfg, responded / len(probes)
                ),
                evidence=evidence,
            )
        )

    anomaly = [
        probe
        for probe in tcp
        if "anomaly" in probe.kinds or "fin_variant" in probe.kinds
    ]
    if len(anomaly) >= cfg.min_anomaly_probes:
        combos = sorted(
            {flags_to_text(flags) for probe in anomaly for flags in probe.flags_seen}
        )
        findings.append(
            _finding(
                session,
                "os_fingerprint",
                ports=len(anomaly),
                confidence=_confidence(len(anomaly), len(tcp), cfg, 0.5),
                evidence=[
                    f"{len(anomaly)} probe(s) used flag combinations a normal TCP stack "
                    f"never emits: {', '.join(combos)}",
                    f"ports: {_ports(anomaly)}",
                ],
            )
        )

    return findings


def _detect_sweeps(analysis: Analysis, cfg: DetectionConfig) -> list[Finding]:
    findings: list[Finding] = []
    sweep_scanners: set[str] = set()

    for scanner, targets in analysis.echo_targets.items():
        if len(targets) < cfg.min_hosts:
            continue
        sweep_scanners.add(scanner)
        findings.append(
            Finding(
                technique="host_sweep",
                title=TECHNIQUES["host_sweep"][0],
                scanner=scanner,
                target=f"{len(targets)} hosts",
                start=analysis.first_ts,
                end=analysis.last_ts,
                ports=len(targets),
                confidence=_sweep_confidence(len(targets), cfg),
                severity="high",
                evidence=[
                    f"ICMP host-discovery probes sent to {len(targets)} distinct hosts",
                    f"sample: {_sample(sorted(targets))}",
                ],
            )
        )

    for (scanner, dport), targets in analysis.syn_targets.items():
        if len(targets) < cfg.min_hosts:
            continue
        if scanner in sweep_scanners and dport in DISCOVERY_PORTS:
            continue  # part of the same ping sweep, not a horizontal service sweep
        findings.append(
            Finding(
                technique="port_sweep",
                title=TECHNIQUES["port_sweep"][0],
                scanner=scanner,
                target=f"{len(targets)} hosts",
                start=analysis.first_ts,
                end=analysis.last_ts,
                ports=1,
                confidence=_sweep_confidence(len(targets), cfg),
                severity="high",
                evidence=[
                    f"TCP port {dport} probed on {len(targets)} distinct hosts",
                    f"sample: {_sample(sorted(targets))}",
                ],
            )
        )

    return findings


# ------------------------------------------------------------------ helpers


def _finding(
    session: ScanSession,
    technique: str,
    *,
    ports: int,
    confidence: float,
    evidence: list[str],
    probe_volume: int | None = None,
) -> Finding:
    # Severity follows the number of ports the scanner actually touched: a
    # connect scan that found 4 open ports still swept the whole range.
    volume = session.port_count if probe_volume is None else probe_volume
    return Finding(
        technique=technique,
        title=TECHNIQUES[technique][0],
        scanner=session.scanner,
        target=session.target,
        start=session.start,
        end=session.end,
        ports=ports,
        confidence=confidence,
        severity=_severity(max(ports, volume)),
        evidence=evidence,
    )


def _confidence(
    count: int,
    total: int,
    cfg: DetectionConfig,
    response_ratio: float,
    *,
    full_scale: int | None = None,
) -> float:
    scale = full_scale if full_scale else 3 * cfg.min_ports
    volume = min(1.0, count / max(1, scale))
    purity = count / max(1, total)
    score = 0.40 + 0.35 * volume + 0.25 * purity
    if response_ratio:
        score += 0.05 * min(1.0, response_ratio)
    if response_ratio == 0.0:
        score -= 0.10
    return round(min(score, 0.99), 2)


def _sweep_confidence(count: int, cfg: DetectionConfig) -> float:
    return round(min(0.99, 0.55 + 0.40 * min(1.0, count / (3 * cfg.min_hosts))), 2)


def _severity(ports: int) -> str:
    if ports >= 100:
        return "high"
    if ports >= 30:
        return "medium"
    return "low"


def _flag_evidence(technique: str, probes: list[PortProbe]) -> str:
    if technique == "xmas":
        return (
            f"{len(probes)} probes used the 'Christmas tree' FIN+PSH+URG "
            "combination (nmap -sX)"
        )
    if technique == "null":
        return f"{len(probes)} TCP segments had no flags set at all (nmap -sN)"
    if technique == "fin":
        return f"{len(probes)} bare FIN segments sent to closed ports (nmap -sF)"
    if technique == "maimon":
        return f"{len(probes)} FIN+ACK segments to ports with no prior handshake (nmap -sM)"
    return (
        f"{len(probes)} ACK-only segments to ports with no prior handshake "
        "(nmap -sA firewall mapping)"
    )


def _ports(probes: list[PortProbe], limit: int = 12) -> str:
    return _ports_text((probe.port for probe in probes), limit)


def _ports_text(ports, limit: int = 12) -> str:
    ordered = sorted(set(ports))
    if not ordered:
        return "none"
    shown = ", ".join(str(port) for port in ordered[:limit])
    if len(ordered) > limit:
        return f"{shown} (+{len(ordered) - limit} more)"
    return shown


def _sample(items: list[str], limit: int = 5) -> str:
    shown = ", ".join(items[:limit])
    if len(items) > limit:
        return f"{shown} (+{len(items) - limit} more)"
    return shown


def _merge(findings: list[Finding]) -> list[Finding]:
    """Collapse repeated detections of the same technique/flow into one finding."""
    merged: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        key = (finding.technique, finding.scanner, finding.target)
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        existing.sessions += finding.sessions
        existing.ports = max(existing.ports, finding.ports)
        existing.confidence = max(existing.confidence, finding.confidence)
        existing.start = min(existing.start, finding.start)
        existing.end = max(existing.end, finding.end)
        for line in finding.evidence:
            if line not in existing.evidence:
                existing.evidence.append(line)

    return sorted(
        merged.values(),
        key=lambda item: (-item.confidence, item.scanner, item.technique),
    )

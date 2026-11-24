"""Human-readable and JSON rendering of analysis reports."""

from __future__ import annotations

from datetime import datetime

from .models import Report

_COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "green": "\033[32m",
}


def _stamp(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def render_text(report: Report, color: bool = False) -> str:
    """Render a report for a terminal."""
    paint = (
        (lambda name, text: f"{_COLORS[name]}{text}{_COLORS['reset']}")
        if color
        else (lambda name, text: text)
    )

    lines = [
        paint("bold", "portscan - network reconnaissance report"),
        paint("dim", f"capture : {report.capture}"),
        f"traffic : {report.packets} packets "
        f"(TCP {report.tcp_packets}, UDP {report.udp_packets}, "
        f"ICMP {report.icmp_packets}) in {report.duration:.2f}s",
    ]
    if report.skipped_packets:
        lines.append(f"skipped : {report.skipped_packets} undecodable frame(s)")
    lines.append("")

    if not report.findings:
        lines.append(paint("green", "No reconnaissance activity detected."))
        return "\n".join(lines)

    lines.append(paint("bold", f"{len(report.findings)} finding(s)"))
    for index, finding in enumerate(report.findings, start=1):
        header = (
            f"{index:>2}. [{finding.severity.upper():<6}] {finding.title}"
            f"   confidence {finding.confidence:.2f}"
        )
        lines.append("")
        lines.append(paint(finding.severity, header))
        lines.append(f"    scanner : {finding.scanner}")
        lines.append(f"    target  : {finding.target}")
        lines.append(
            f"    window  : {_stamp(finding.start)} -> {_stamp(finding.end)}"
            f" ({finding.end - finding.start:.2f}s)"
        )
        lines.append(f"    ports   : {finding.ports}")
        if finding.sessions > 1:
            lines.append(f"    bursts  : {finding.sessions}")
        lines.append("    evidence:")
        for line in finding.evidence:
            lines.append(f"      - {line}")

    return "\n".join(lines)


def report_to_dict(report: Report) -> dict:
    """Machine-readable form of a report."""
    return {
        "capture": report.capture,
        "packets": {
            "total": report.packets,
            "tcp": report.tcp_packets,
            "udp": report.udp_packets,
            "icmp": report.icmp_packets,
            "skipped": report.skipped_packets,
        },
        "duration_seconds": round(report.duration, 3),
        "findings": [
            {
                "technique": finding.technique,
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "scanner": finding.scanner,
                "target": finding.target,
                "ports": finding.ports,
                "sessions": finding.sessions,
                "start": _stamp(finding.start),
                "end": _stamp(finding.end),
                "evidence": finding.evidence,
            }
            for finding in report.findings
        ],
        "config": report.config,
    }

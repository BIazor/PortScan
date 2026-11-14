"""Command line interface for scanwatch."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .detectors import DetectionConfig, detect
from .models import Report
from .pcapio import CaptureError, read_packets
from .report import render_text, report_to_dict
from .tracker import ActivityTracker, TrackerConfig


def analyze_capture(
    path: str | Path,
    *,
    detection: DetectionConfig | None = None,
    session_gap: float = 30.0,
) -> Report:
    """Parse *path* and return a fully populated :class:`Report`."""
    detection = detection or DetectionConfig()
    packets, skipped = read_packets(str(path))

    tracker = ActivityTracker(TrackerConfig(session_gap=session_gap))
    for packet in packets:
        tracker.feed(packet)
    analysis = tracker.finish()

    report = Report(
        capture=str(path),
        packets=len(packets),
        tcp_packets=sum(1 for packet in packets if packet.proto == "TCP"),
        udp_packets=sum(1 for packet in packets if packet.proto == "UDP"),
        icmp_packets=sum(1 for packet in packets if packet.proto == "ICMP"),
        skipped_packets=skipped,
        start=min((packet.ts for packet in packets), default=0.0),
        end=max((packet.ts for packet in packets), default=0.0),
        findings=detect(analysis, detection),
        config={
            "min_ports": detection.min_ports,
            "min_hosts": detection.min_hosts,
            "min_connect_ports": detection.min_connect_ports,
            "min_version_ports": detection.min_version_ports,
            "min_udp_ports": detection.min_udp_ports,
            "min_anomaly_probes": detection.min_anomaly_probes,
            "session_gap": session_gap,
        },
    )
    return report


def _add_detection_options(parser: argparse.ArgumentParser) -> None:
    defaults = DetectionConfig()
    parser.add_argument(
        "--min-ports",
        type=int,
        default=defaults.min_ports,
        help="distinct ports required for a port-scan finding (default: %(default)s)",
    )
    parser.add_argument(
        "--min-hosts",
        type=int,
        default=defaults.min_hosts,
        help="distinct hosts required for a sweep finding (default: %(default)s)",
    )
    parser.add_argument(
        "--min-connect-ports",
        type=int,
        default=defaults.min_connect_ports,
        help="handshakes required to call a connect scan (default: %(default)s)",
    )
    parser.add_argument(
        "--min-version-ports",
        type=int,
        default=defaults.min_version_ports,
        help="ports with service probes required for -sV (default: %(default)s)",
    )
    parser.add_argument(
        "--min-udp-ports",
        type=int,
        default=defaults.min_udp_ports,
        help="distinct ports required for a UDP scan (default: %(default)s)",
    )
    parser.add_argument(
        "--min-anomaly-probes",
        type=int,
        default=defaults.min_anomaly_probes,
        help="malformed-flag probes required for OS fingerprinting (default: %(default)s)",
    )
    parser.add_argument(
        "--session-gap",
        type=float,
        default=30.0,
        help="idle seconds before probes start a new session (default: %(default)s)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanwatch",
        description="Detect Nmap reconnaissance techniques in pcap captures.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze", help="analyze one or more pcap/pcapng captures"
    )
    analyze.add_argument("captures", nargs="+", help="capture file(s) to analyze")
    analyze.add_argument(
        "--json", action="store_true", help="print JSON instead of a text report"
    )
    analyze.add_argument(
        "--no-color", action="store_true", help="disable ANSI colors in the text report"
    )
    analyze.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="exit with status 1 when reconnaissance is detected",
    )
    _add_detection_options(analyze)

    synth = subparsers.add_parser(
        "synth", help="write labelled synthetic Nmap captures for offline testing"
    )
    synth.add_argument("out_dir", nargs="?", default="samples", help="output directory")
    return parser


def _run_analyze(args: argparse.Namespace) -> int:
    detection = DetectionConfig(
        min_ports=args.min_ports,
        min_hosts=args.min_hosts,
        min_connect_ports=args.min_connect_ports,
        min_version_ports=args.min_version_ports,
        min_udp_ports=args.min_udp_ports,
        min_anomaly_probes=args.min_anomaly_probes,
    )
    reports: list[Report] = []
    errors: list[str] = []
    for capture in args.captures:
        try:
            reports.append(
                analyze_capture(
                    capture, detection=detection, session_gap=args.session_gap
                )
            )
        except CaptureError as exc:
            # Keep going: one unreadable file should not discard the others.
            errors.append(str(exc))

    if reports:
        if args.json:
            payload = (
                report_to_dict(reports[0])
                if len(reports) == 1
                else [report_to_dict(report) for report in reports]
            )
            print(json.dumps(payload, indent=2))
        else:
            color = sys.stdout.isatty() and not args.no_color
            for index, report in enumerate(reports):
                if index:
                    print()
                print(render_text(report, color=color))

    for message in errors:
        print(f"scanwatch: {message}", file=sys.stderr)
    if errors:
        return 2
    if args.fail_on_findings and any(report.findings for report in reports):
        return 1
    return 0


def _run_synth(args: argparse.Namespace) -> int:
    from .synth import write_all

    try:
        manifest = write_all(args.out_dir)
    except OSError as exc:
        print(f"scanwatch: cannot write to {args.out_dir}: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {len(manifest)} captures to {Path(args.out_dir)}")
    for name in sorted(manifest):
        expected = ", ".join(manifest[name]["expected"]) or "no findings"
        print(f"  {name + '.pcap':<20} expect: {expected}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        return _run_analyze(args)
    if args.command == "synth":
        return _run_synth(args)
    return 2

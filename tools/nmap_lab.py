#!/usr/bin/env python3
"""Generate real Nmap traffic, capture it with Npcap, and score the detector.

This is the validation harness behind the project's accuracy claims. For every
Nmap technique it:

1. opens a handful of local listening ports (so scans have real services),
2. starts an Npcap capture on the loopback adapter,
3. runs the actual ``nmap`` scan against this host,
4. writes the capture to ``captures/real/<scenario>.pcap``,
5. runs scanwatch over that capture and compares the result with the expected
   technique.

Targets are restricted to loopback/private addresses: this is a lab, not a
scanner.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import npcap_capture  # noqa: E402
from scanwatch.cli import analyze_capture  # noqa: E402
from scanwatch.detectors import DetectionConfig  # noqa: E402

TCP_PORTS = "1-400,20001-20008"
LISTEN_PORTS = tuple(range(20001, 20009))
# Deliberately unrecognised by Nmap's service probes: it reads the banner,
# fails to match it, and then sends its probe payloads to identify the service.
BANNER = b"SCANWATCH-LAB 1.0 ready\r\n"
BASE_ARGS = ["-Pn", "-n", "-T4", "--max-retries", "1"]

OUT_DIR = PROJECT_ROOT / "captures" / "real"


@dataclass
class Scenario:
    name: str
    args: list[str]
    expected: tuple[str, ...]
    description: str
    nmap_ok: bool = True


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        "syn_scan",
        ["-sS", "-p", TCP_PORTS, "--min-rate", "800"],
        ("syn",),
        "half-open SYN sweep, RST+ACK from closed ports",
    ),
    Scenario(
        "connect_scan",
        ["-sT", "-p", TCP_PORTS, "--min-rate", "800"],
        ("connect",),
        "full connect() sweep, handshakes on the listening ports",
    ),
    Scenario(
        "fin_scan",
        ["-sF", "-p", TCP_PORTS, "--min-rate", "800"],
        ("fin",),
        "bare FIN segments",
    ),
    Scenario(
        "xmas_scan",
        ["-sX", "-p", TCP_PORTS, "--min-rate", "800"],
        ("xmas",),
        "FIN+PSH+URG probes",
    ),
    Scenario(
        "null_scan",
        ["-sN", "-p", TCP_PORTS, "--min-rate", "800"],
        ("null",),
        "TCP segments with no flags",
    ),
    Scenario(
        "ack_scan",
        ["-sA", "-p", TCP_PORTS, "--min-rate", "800"],
        ("ack",),
        "ACK-only firewall mapping",
    ),
    Scenario(
        "maimon_scan",
        ["-sM", "-p", TCP_PORTS, "--min-rate", "800"],
        ("maimon",),
        "FIN+ACK probes",
    ),
    Scenario(
        "udp_scan",
        ["-sU", "--top-ports", "60", "--min-rate", "300"],
        ("udp",),
        "UDP datagrams, ICMP port-unreachable for closed ports",
    ),
    Scenario(
        "version_scan",
        ["-sV", "-p", ",".join(str(p) for p in LISTEN_PORTS), "--version-intensity", "2"],
        ("version",),
        "service probes over completed handshakes",
    ),
    Scenario(
        "os_fingerprint",
        ["-O", "--osscan-limit", "-p", TCP_PORTS],
        # -O runs a SYN port scan before the fingerprint probes, so both
        # techniques are genuinely present in the capture.
        ("syn", "os_fingerprint"),
        "illegal flag combinations from OS detection (plus its SYN port scan)",
    ),
)


class BannerListeners:
    """Fake services on the lab ports for version detection to probe.

    The banner must be something Nmap cannot identify: a recognised banner
    (e.g. SSH) ends service detection immediately and no application data is
    ever sent, which would make ``-sV`` look like a connect scan.
    """

    def __init__(self, ports: tuple[int, ...]) -> None:
        self.ports = ports
        self._stop = threading.Event()
        self._sockets: list[socket.socket] = []

    def start(self) -> None:
        start_barrier = threading.Event()
        for port in self.ports:
            thread = threading.Thread(
                target=self._serve, args=(port, start_barrier), daemon=True
            )
            thread.start()
            start_barrier.wait(timeout=2)

    def _serve(self, port: int, ready: threading.Event) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", port))
            server.listen(32)
            server.settimeout(0.2)
        except OSError as exc:
            print(f"  ! cannot listen on {port}: {exc}", file=sys.stderr)
            ready.set()
            return
        self._sockets.append(server)
        ready.set()
        while not self._stop.is_set():
            try:
                connection, _ = server.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(
                target=self._handle, args=(connection,), daemon=True
            ).start()

    @staticmethod
    def _handle(connection: socket.socket) -> None:
        try:
            connection.settimeout(2.0)
            connection.sendall(BANNER)
            for _ in range(3):
                if not connection.recv(4096):
                    break
        except (socket.timeout, OSError):
            pass
        finally:
            connection.close()

    def stop(self) -> None:
        self._stop.set()
        for server in self._sockets:
            try:
                server.close()
            except OSError:
                pass


def _nmap_binary(explicit: str | None) -> str:
    if explicit:
        return explicit
    found = shutil.which("nmap")
    if found:
        return found
    fallback = Path(r"C:\Program Files (x86)\Nmap\nmap.exe")
    if fallback.exists():
        return str(fallback)
    raise SystemExit("nmap not found: install it or pass --nmap PATH")


def _assert_safe_target(target: str) -> None:
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise SystemExit(f"target must be a literal IP address: {target}") from exc
    if not (address.is_loopback or address.is_private):
        raise SystemExit(
            f"refusing to scan {target}: this lab only scans loopback/private hosts"
        )


def _run_scan(
    scenario: Scenario,
    *,
    nmap: str,
    target: str,
    device: str,
) -> tuple[Path, Path, float, str]:
    capture = npcap_capture.Capture(device=device)
    capture.start()
    try:
        time.sleep(0.3)
        command = [nmap, *BASE_ARGS, *scenario.args, target]
        started = time.monotonic()
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=240
        )
        elapsed = time.monotonic() - started
        time.sleep(0.6)
    finally:
        frames = capture.stop()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pcap_path = OUT_DIR / f"{scenario.name}.pcap"
    log_path = OUT_DIR / f"{scenario.name}.nmap.txt"
    npcap_capture.write_pcap(pcap_path, frames, capture.linktype)
    log_path.write_text(
        f"$ {' '.join(command)}\n\n{process.stdout}\n{process.stderr}",
        encoding="utf-8",
    )
    output = (process.stdout or "") + (process.stderr or "")
    return pcap_path, log_path, elapsed, output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate scanwatch against real Nmap traffic."
    )
    parser.add_argument("--target", default="127.0.0.1", help="loopback/private IP")
    parser.add_argument("--device", help="Npcap device name (default: auto)")
    parser.add_argument("--nmap", help="path to nmap.exe")
    parser.add_argument(
        "--only", help="comma separated scenario names (default: all)"
    )
    parser.add_argument(
        "--min-ports",
        type=int,
        default=15,
        help="detection threshold passed through to scanwatch",
    )
    args = parser.parse_args(argv)

    _assert_safe_target(args.target)
    nmap = _nmap_binary(args.nmap)
    device = args.device or npcap_capture.find_device_for_ip(args.target)

    selected = [
        scenario
        for scenario in SCENARIOS
        if not args.only or scenario.name in args.only.split(",")
    ]
    if not selected:
        raise SystemExit("no matching scenarios")

    print(f"nmap    : {nmap}")
    print(f"target  : {args.target}")
    print(f"device  : {device}")
    print(f"captures: {OUT_DIR}")
    print()

    listeners = BannerListeners(LISTEN_PORTS)
    listeners.start()
    detection = DetectionConfig(min_ports=args.min_ports)
    results: list[dict] = []

    try:
        for scenario in selected:
            print(f"[*] {scenario.name}: {scenario.description}")
            pcap_path, log_path, elapsed, nmap_output = _run_scan(
                scenario, nmap=nmap, target=args.target, device=device
            )
            report = analyze_capture(pcap_path, detection=detection)
            detected = {finding.technique for finding in report.findings}
            expected = set(scenario.expected)
            missing = sorted(expected - detected)
            extra = sorted(detected - expected)
            verdict = "PASS" if not missing else "FAIL"

            confidence = max(
                (finding.confidence for finding in report.findings), default=0.0
            )
            results.append(
                {
                    "scenario": scenario.name,
                    "description": scenario.description,
                    "nmap_args": scenario.args,
                    "expected": sorted(expected),
                    "detected": sorted(detected),
                    "missing": missing,
                    "extra": extra,
                    "verdict": verdict,
                    "confidence": confidence,
                    "packets": report.packets,
                    "scan_seconds": round(elapsed, 2),
                    "capture": str(pcap_path.relative_to(PROJECT_ROOT)),
                    "nmap_log": str(log_path.relative_to(PROJECT_ROOT)),
                    "findings": [
                        {
                            "technique": finding.technique,
                            "severity": finding.severity,
                            "confidence": finding.confidence,
                            "ports": finding.ports,
                            "evidence": finding.evidence,
                        }
                        for finding in report.findings
                    ],
                }
            )
            print(
                f"    {verdict}  {report.packets:>5} packets  "
                f"detected: {', '.join(sorted(detected)) or 'none'}"
                + (f"  missing: {', '.join(missing)}" if missing else "")
                + (f"  extra: {', '.join(extra)}" if extra else "")
            )
            if not report.packets:
                print("    ! capture was empty - is the target traffic on this adapter?")
            if "not supported" in nmap_output.lower():
                print("    ! nmap reported an unsupported feature")
    finally:
        listeners.stop()

    passed = sum(1 for item in results if item["verdict"] == "PASS")
    expected_total = sum(len(item["expected"]) for item in results)
    detected_total = sum(
        len(set(item["expected"]) & set(item["detected"])) for item in results
    )
    extras_total = sum(len(item["extra"]) for item in results)
    recall = detected_total / expected_total if expected_total else 0.0
    precision = (
        detected_total / (detected_total + extras_total) if detected_total + extras_total else 0.0
    )

    print()
    print(f"scenarios passed : {passed}/{len(results)}")
    print(f"technique recall : {recall:.0%}  ({detected_total}/{expected_total})")
    print(f"technique precision: {precision:.0%}")
    for item in results:
        if item["verdict"] != "PASS":
            print(f"  FAIL {item['scenario']}: missing {item['missing']}")

    summary = {
        "target": args.target,
        "device": device,
        "nmap": nmap,
        "min_ports": args.min_ports,
        "scenarios": results,
        "summary": {
            "passed": passed,
            "total": len(results),
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "detected_techniques": detected_total,
            "expected_techniques": expected_total,
            "extra_findings": extras_total,
        },
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "validation.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(f"report written to {OUT_DIR / 'validation.json'}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

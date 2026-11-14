"""Generate labelled pcap files that reproduce each Nmap scan's wire signature.

These captures make the detector testable and demonstrable on machines without
Nmap or a capture driver. They impersonate Nmap's flag choices, its fixed
1024-byte scan window and its response patterns, but they are *synthetic*: the
real-traffic validation lives in ``tools/nmap_lab.py``.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Callable

import dpkt

from .models import ACK, FIN, PSH, RST, SYN, URG

BASE_TS = 1_700_000_000.0
SCANNER = "10.10.0.99"
TARGET = "10.10.0.50"
OPEN_PORTS = (22, 80, 443, 8080)
CLIENT = "10.10.0.10"


def _mac(ip: str) -> bytes:
    return b"\x02\x00" + socket.inet_aton(ip)[1:]


def _ip_frame(src: str, dst: str, proto: int, data, length: int, *, ttl=64, ip_id=1) -> bytes:
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src),
        dst=socket.inet_aton(dst),
        p=proto,
        ttl=ttl,
        id=ip_id,
        data=data,
    )
    ip.len = ip.__hdr_len__ + length
    eth = dpkt.ethernet.Ethernet(
        src=_mac(src), dst=_mac(dst), type=dpkt.ethernet.ETH_TYPE_IP, data=ip
    )
    return eth.pack()


def _tcp_frame(
    src, dst, sport, dport, flags, *, seq=1000, ack=0, win=1024, payload=b""
) -> bytes:
    tcp = dpkt.tcp.TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, win=win, data=payload
    )
    header = len(tcp.pack_hdr())
    return _ip_frame(src, dst, dpkt.ip.IP_PROTO_TCP, tcp, header + len(payload))


def _udp_frame(src, dst, sport, dport, payload=b"") -> bytes:
    udp = dpkt.udp.UDP(sport=sport, dport=dport, ulen=8 + len(payload), data=payload)
    return _ip_frame(src, dst, dpkt.ip.IP_PROTO_UDP, udp, udp.ulen)


def _icmp_frame(src, dst, icmp_type, code, data) -> bytes:
    icmp = dpkt.icmp.ICMP(type=icmp_type, code=code, data=data)
    raw = icmp.pack()
    return _ip_frame(src, dst, dpkt.ip.IP_PROTO_ICMP, raw, len(raw))


class _Traffic:
    """Tiny packet emitter that keeps a monotonically increasing timestamp."""

    def __init__(self, scanner: str = SCANNER, target: str = TARGET) -> None:
        self.scanner = scanner
        self.target = target
        self.ts = BASE_TS
        self.sport = 54321
        self.seq = 1000
        self.frames: list[tuple[float, bytes]] = []

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFFFFFFFF
        return self.seq

    def _emit(self, frame: bytes, advance: float) -> None:
        self.frames.append((self.ts, frame))
        self.ts += advance

    def probe(
        self, flags: int, port: int, *, win=1024, payload=b"", seq=None, advance=0.002
    ) -> None:
        self._emit(
            _tcp_frame(
                self.scanner,
                self.target,
                self.sport,
                port,
                flags,
                seq=self._next_seq() if seq is None else seq,
                win=win,
                payload=payload,
            ),
            advance,
        )

    def reply(
        self, flags: int, port: int, *, win=0, payload=b"", seq=None, advance=0.001
    ) -> None:
        self._emit(
            _tcp_frame(
                self.target,
                self.scanner,
                port,
                self.sport,
                flags,
                seq=self._next_seq() if seq is None else seq,
                win=win,
                payload=payload,
            ),
            advance,
        )

    def udp_probe(self, port: int, payload=b"\x00" * 8, advance=0.002) -> None:
        self._emit(
            _udp_frame(self.scanner, self.target, self.sport, port, payload), advance
        )

    def udp_reply(self, port: int, payload=b"\x00" * 8, advance=0.001) -> None:
        self._emit(
            _udp_frame(self.target, self.scanner, port, self.sport, payload), advance
        )

    def icmp_echo(self, advance=0.002) -> None:
        echo = dpkt.icmp.ICMP.Echo(id=0x1234, seq=1, data=b"scanwatch")
        self._emit(
            _icmp_frame(self.scanner, self.target, 8, 0, echo), advance
        )

    def icmp_unreachable(self, port: int, advance=0.001) -> None:
        inner = dpkt.ip.IP(
            src=socket.inet_aton(self.scanner),
            dst=socket.inet_aton(self.target),
            p=dpkt.ip.IP_PROTO_UDP,
            ttl=1,
            data=dpkt.udp.UDP(sport=self.sport, dport=port),
        )
        inner.len = inner.__hdr_len__ + 8
        unreachable = dpkt.icmp.ICMP.Unreach(data=inner.pack()[:28])
        self._emit(
            _icmp_frame(self.target, self.scanner, 3, 3, unreachable), advance
        )


def _ports(count: int, excluded) -> list[int]:
    ports: list[int] = []
    port = 1
    while len(ports) < count:
        if port not in excluded:
            ports.append(port)
        port += 1
    return ports


def _scan_ports(count: int) -> list[int]:
    """A port range that includes the emulated listening ports."""
    return sorted(_ports(count - len(OPEN_PORTS), OPEN_PORTS) + list(OPEN_PORTS))


# --------------------------------------------------------------- scenarios


def _syn_scan() -> _Traffic:
    traffic = _Traffic()
    for port in _scan_ports(300):
        traffic.probe(SYN, port, win=1024)
        if port in OPEN_PORTS:
            traffic.reply(SYN | ACK, port, win=64240)
            traffic.probe(RST, port, win=0)
        else:
            traffic.reply(RST | ACK, port, win=0)
    return traffic


def _connect_scan() -> _Traffic:
    traffic = _Traffic()
    for port in _scan_ports(200):
        traffic.probe(SYN, port)
        if port in OPEN_PORTS:
            traffic.reply(SYN | ACK, port, win=64240)
            traffic.probe(ACK, port)
            traffic.probe(RST, port, win=0)
        else:
            traffic.reply(RST | ACK, port, win=0)
    return traffic


def _fin_scan() -> _Traffic:
    traffic = _Traffic()
    for port in _scan_ports(200):
        traffic.probe(FIN, port)
        if port not in OPEN_PORTS:
            traffic.reply(RST | ACK, port, win=0)
    return traffic


def _xmas_scan() -> _Traffic:
    traffic = _Traffic()
    for port in _scan_ports(200):
        traffic.probe(FIN | PSH | URG, port, win=1024)
        if port not in OPEN_PORTS:
            traffic.reply(RST | ACK, port, win=0)
    return traffic


def _null_scan() -> _Traffic:
    traffic = _Traffic()
    for port in _scan_ports(200):
        traffic.probe(0, port, win=1024)
        if port not in OPEN_PORTS:
            traffic.reply(RST | ACK, port, win=0)
    return traffic


def _ack_scan() -> _Traffic:
    traffic = _Traffic()
    for port in _scan_ports(200):
        traffic.probe(ACK, port, win=1024, seq=4242)
        traffic.reply(RST | ACK, port, win=0)
    return traffic


def _maimon_scan() -> _Traffic:
    traffic = _Traffic()
    for port in _scan_ports(200):
        traffic.probe(FIN | ACK, port, win=1024, seq=4242)
        if port not in OPEN_PORTS:
            traffic.reply(RST | ACK, port, win=0)
    return traffic


def _udp_scan() -> _Traffic:
    traffic = _Traffic()
    for port in _ports(80, OPEN_PORTS):
        traffic.udp_probe(port)
        traffic.icmp_unreachable(port)
    return traffic


def _version_scan() -> _Traffic:
    traffic = _Traffic()
    for port in OPEN_PORTS:
        for _ in range(2):  # nmap repeats its probes when a service is quiet
            traffic.probe(SYN, port)
            traffic.reply(SYN | ACK, port, win=64240)
            traffic.probe(ACK, port)
            traffic.probe(PSH | ACK, port, payload=b"GET / HTTP/1.0\r\n\r\n")
            traffic.probe(PSH | ACK, port, payload=b"\x00" * 16)
            traffic.reply(RST | ACK, port, win=0)
    return traffic


def _os_fingerprint() -> _Traffic:
    traffic = _Traffic()
    traffic.probe(SYN, 22)
    traffic.reply(SYN | ACK, 22, win=64240)
    traffic.probe(RST, 22, win=0)
    traffic.probe(SYN, 1)
    traffic.reply(RST | ACK, 1, win=0)
    traffic.probe(SYN | FIN, 1, win=1024)  # T7-style illegal combination
    traffic.probe(SYN | FIN, 22, win=1024)
    traffic.probe(SYN | PSH, 1, win=1024)
    traffic.probe(ACK, 22, win=1024, seq=4242)
    return traffic


def _port_sweep() -> _Traffic:
    traffic = _Traffic()
    for index in range(12):
        traffic.target = f"10.10.0.{100 + index}"
        traffic.probe(SYN, 445)
        traffic.reply(RST | ACK, 445, win=0)
    return traffic


def _host_sweep() -> _Traffic:
    traffic = _Traffic()
    for index in range(12):
        traffic.target = f"10.10.0.{100 + index}"
        traffic.icmp_echo()
        traffic.probe(SYN, 80)
        traffic.reply(RST | ACK, 80, win=0)
    return traffic


def _benign_web() -> _Traffic:
    traffic = _Traffic(scanner=CLIENT, target="93.184.216.34")
    for _ in range(2):
        traffic.probe(SYN, 80)
        traffic.reply(SYN | ACK, 80, win=65535)
        traffic.probe(ACK, 80)
        traffic.probe(
            PSH | ACK, 80, payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        traffic.reply(
            PSH | ACK, 80, payload=b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 200
        )
        traffic.probe(FIN | ACK, 80)
        traffic.reply(FIN | ACK, 80)
    return traffic


def _benign_udp_discovery() -> _Traffic:
    """Service-discovery chatter: one source poking a short run of ports.

    Matches the 10-datagram burst seen on loopback during validation; a burst
    this narrow is ordinary local discovery, not a UDP scan.
    """
    traffic = _Traffic()
    for port in range(10010, 10020):
        traffic.udp_probe(port, payload=b"\x00" * 2872)
    return traffic


def _benign_dns() -> _Traffic:
    traffic = _Traffic(scanner=CLIENT, target="10.10.0.1")
    for index in range(3):
        traffic.udp_probe(53, payload=b"\x12\x34\x01\x00" + bytes([index]))
        traffic.udp_reply(53, payload=b"\x12\x34\x81\x80" + bytes(20))
    return traffic


SCENARIOS: dict[str, tuple[str, tuple[str, ...], Callable[[], _Traffic]]] = {
    "syn_scan": ("Half-open SYN scan of 300 ports", ("syn",), _syn_scan),
    "connect_scan": ("Connect scan with completed handshakes", ("connect",), _connect_scan),
    "fin_scan": ("FIN scan", ("fin",), _fin_scan),
    "xmas_scan": ("XMAS scan", ("xmas",), _xmas_scan),
    "null_scan": ("NULL scan", ("null",), _null_scan),
    "ack_scan": ("ACK firewall-mapping scan", ("ack",), _ack_scan),
    "maimon_scan": ("Maimon (FIN+ACK) scan", ("maimon",), _maimon_scan),
    "udp_scan": ("UDP scan with port-unreachable replies", ("udp",), _udp_scan),
    "version_scan": ("Service/version detection", ("version",), _version_scan),
    "os_fingerprint": ("OS fingerprint probes", ("os_fingerprint",), _os_fingerprint),
    "port_sweep": ("Horizontal sweep of port 445", ("port_sweep",), _port_sweep),
    "host_sweep": ("Ping sweep over 12 hosts", ("host_sweep",), _host_sweep),
    "benign_web": ("Normal HTTP browsing", (), _benign_web),
    "benign_udp_discovery": (
        "UDP service discovery across 10 ports",
        (),
        _benign_udp_discovery,
    ),
    "benign_dns": ("Normal DNS lookups", (), _benign_dns),
}


def write_scenario(name: str, path: str | Path) -> tuple[str, ...]:
    """Write one scenario to *path* and return the techniques it should trigger."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _, expected, build = SCENARIOS[name]
    frames = build().frames
    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle, snaplen=65535)
        for ts, frame in frames:
            writer.writepkt(frame, ts=ts)
    return expected


def write_all(out_dir: str | Path) -> dict:
    """Write every scenario plus ``labels.json`` into *out_dir*."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, dict] = {}
    for name in sorted(SCENARIOS):
        title, expected, _ = SCENARIOS[name]
        path = out_dir / f"{name}.pcap"
        write_scenario(name, path)
        manifest[name] = {
            "title": title,
            "expected": list(expected),
            "path": path.name,
        }
    (out_dir / "labels.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest

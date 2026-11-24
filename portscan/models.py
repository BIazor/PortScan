"""Core data structures shared by the parser, the tracker and the detectors.

The pipeline is deliberately linear:

``pcapio``  -> :class:`Packet`      (one record per TCP/UDP/ICMP message)
``tracker`` -> :class:`ScanSession` (probes grouped per scanner -> target)
``detectors`` -> :class:`Finding`   (one classified reconnaissance technique)
"""

from __future__ import annotations

from dataclasses import dataclass, field

# TCP flag bits (RFC 793 + RFC 3168 for ECE/CWR).
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

_FLAG_NAMES = (
    (FIN, "FIN"),
    (SYN, "SYN"),
    (RST, "RST"),
    (PSH, "PSH"),
    (ACK, "ACK"),
    (URG, "URG"),
    (ECE, "ECE"),
    (CWR, "CWR"),
)


def flags_to_text(flags: int) -> str:
    """Render a TCP flag byte the way Wireshark does (``SYN+ACK``, ``NULL``...)."""
    names = [name for bit, name in _FLAG_NAMES if flags & bit]
    return "+".join(names) if names else "NULL"


@dataclass(slots=True)
class Packet:
    """A single decoded network message.

    ``inner_*`` fields are only populated for ICMP error messages, where the
    quoted packet is what lets us attribute "port unreachable" back to the UDP
    (or TCP) probe that caused it.
    """

    ts: float
    src: str
    dst: str
    proto: str  # "TCP" | "UDP" | "ICMP"
    sport: int = 0
    dport: int = 0
    flags: int = 0
    win: int = 0
    payload_len: int = 0
    icmp_type: int = -1
    icmp_code: int = -1
    inner_src: str = ""
    inner_dst: str = ""
    inner_proto: int = -1
    inner_sport: int = 0
    inner_dport: int = 0


@dataclass
class PortProbe:
    """Everything observed about one scanned destination port.

    Counters rather than booleans are used so retransmissions and repeated
    connections (``nmap -sV`` opens the same port several times) aggregate
    instead of overwriting each other.
    """

    port: int
    proto: str
    kinds: set[str] = field(default_factory=set)
    flags_seen: set[int] = field(default_factory=set)
    windows: set[int] = field(default_factory=set)
    probes: int = 0
    payload: int = 0
    payload_segments: int = 0
    synack: int = 0
    completions: int = 0
    rst_from_target: int = 0
    icmp_unreachable: int = 0

    @property
    def responded(self) -> bool:
        """True when the target said *something* about this port."""
        return bool(self.synack or self.rst_from_target or self.icmp_unreachable)


@dataclass
class ScanSession:
    """Probes sent by one scanner to one target inside one time window."""

    scanner: str
    target: str
    start: float
    end: float
    tcp: dict[int, PortProbe] = field(default_factory=dict)
    udp: dict[int, PortProbe] = field(default_factory=dict)
    last_probe_ts: float = 0.0

    @property
    def tcp_probes(self) -> list[PortProbe]:
        return list(self.tcp.values())

    @property
    def udp_probes(self) -> list[PortProbe]:
        return list(self.udp.values())

    @property
    def port_count(self) -> int:
        return len(self.tcp) + len(self.udp)

    @property
    def duration(self) -> float:
        return max(0.0, self.end - self.start)


@dataclass
class Finding:
    """A classified piece of reconnaissance activity."""

    technique: str
    title: str
    scanner: str
    target: str
    start: float
    end: float
    ports: int
    confidence: float
    severity: str
    evidence: list[str] = field(default_factory=list)
    sessions: int = 1


@dataclass
class Report:
    """Analysis result for a single capture file."""

    capture: str
    packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    skipped_packets: int = 0
    start: float = 0.0
    end: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    config: dict = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return max(0.0, self.end - self.start)

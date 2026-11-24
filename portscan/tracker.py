"""Stateful aggregation of packets into per-(scanner, target) scan sessions.

The tracker is the bridge between raw packets and detection rules. It answers
three questions for the detectors:

* which host probed which host,
* what happened on every probed port (response, handshake, teardown), and
* do the probes belong to one burst of activity or to unrelated traffic?
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import ACK, FIN, RST, SYN, Packet, PortProbe, ScanSession
from .probes import classify_probe

# Ports every host-discovery method probes; used to separate a ping sweep from
# a horizontal service sweep.
DISCOVERY_PORTS = frozenset({22, 80, 443, 445, 3389, 8080})

_ICMP_ECHO_REQUEST = 8
_ICMP_TIMESTAMP_REQUEST = 13
_ICMP_UNREACHABLE = 3


@dataclass
class TrackerConfig:
    #: Idle gap after which probes to the same target count as a new session.
    session_gap: float = 30.0


@dataclass
class Analysis:
    """Everything the tracker learned from one capture."""

    sessions: list[ScanSession] = field(default_factory=list)
    echo_targets: dict[str, set[str]] = field(default_factory=dict)
    syn_targets: dict[tuple[str, int], set[str]] = field(default_factory=dict)
    first_ts: float = 0.0
    last_ts: float = 0.0


class ActivityTracker:
    """Fold packets into :class:`ScanSession` objects as they are read."""

    def __init__(self, config: TrackerConfig | None = None) -> None:
        self.config = config or TrackerConfig()
        self._sessions: list[ScanSession] = []
        self._current: dict[tuple[str, str], ScanSession] = {}
        self._probe_index: dict[tuple[str, str, str, int], PortProbe] = {}
        self._established: set[tuple[str, int, str, int]] = set()
        self._echo: dict[str, set[str]] = {}
        self._syn_targets: dict[tuple[str, int], set[str]] = {}
        self._first: float | None = None
        self._last: float = 0.0

    # ------------------------------------------------------------------ feed

    def feed(self, packet: Packet) -> None:
        if self._first is None:
            self._first = packet.ts
        self._last = max(self._last, packet.ts)

        if packet.proto == "TCP":
            self._feed_tcp(packet)
        elif packet.proto == "UDP":
            self._feed_udp(packet)
        else:
            self._feed_icmp(packet)

    def _feed_tcp(self, packet: Packet) -> None:
        # 1. A response to something we already recorded on this port?
        probe = self._probe_index.get((packet.dst, packet.src, "TCP", packet.sport))
        if probe is not None and self._is_response(packet):
            self._apply_response(probe, packet)
            if (packet.flags & SYN) and (packet.flags & ACK):
                self._mark_established(packet.dst, packet.dport, packet.src, packet.sport)
            return

        # 2. SYN+ACK: the responder's half of any handshake, probe or not.
        if (packet.flags & SYN) and (packet.flags & ACK):
            self._mark_established(packet.dst, packet.dport, packet.src, packet.sport)
            return

        scanner_probe = self._probe_index.get((packet.src, packet.dst, "TCP", packet.dport))

        # 3. Application data on a probed port (``nmap -sV`` banner grabbing).
        if scanner_probe is not None and packet.payload_len:
            scanner_probe.payload += packet.payload_len
            scanner_probe.payload_segments += 1
            return

        # 4. ACK that completes the handshake opened by a bare SYN (``-sT``).
        if packet.flags == ACK and scanner_probe is not None and scanner_probe.synack:
            scanner_probe.completions += 1
            self._mark_established(packet.src, packet.sport, packet.dst, packet.dport)
            return

        # 5. Teardown sent by the scanner (``-sS`` resets open ports, ``-sT``
        #    closes after the handshake). Neither is a probe.
        if packet.flags & RST:
            return
        if (
            (packet.flags & FIN)
            and not (packet.flags & SYN)
            and scanner_probe is not None
            and scanner_probe.synack
        ):
            return

        # 6. Anything left that carries an illegal flag combination is a probe.
        prior = (packet.src, packet.sport, packet.dst, packet.dport) in self._established
        kind = classify_probe(packet.flags, prior_handshake=prior)
        if kind is None:
            return

        session = self._session_for(packet.src, packet.dst, packet.ts)
        probe = session.tcp.get(packet.dport)
        if probe is None:
            probe = PortProbe(port=packet.dport, proto="TCP")
            session.tcp[packet.dport] = probe
            self._probe_index[(packet.src, packet.dst, "TCP", packet.dport)] = probe

        probe.probes += 1
        probe.kinds.add(kind)
        probe.flags_seen.add(packet.flags)
        probe.windows.add(packet.win)
        probe.payload += packet.payload_len
        if packet.payload_len:
            probe.payload_segments += 1

        session.end = max(session.end, packet.ts)
        session.last_probe_ts = packet.ts
        self._syn_targets.setdefault((packet.src, packet.dport), set()).add(packet.dst)

    def _feed_udp(self, packet: Packet) -> None:
        probe = self._probe_index.get((packet.dst, packet.src, "UDP", packet.sport))
        if probe is not None:
            return

        session = self._session_for(packet.src, packet.dst, packet.ts)
        probe = session.udp.get(packet.dport)
        if probe is None:
            probe = PortProbe(port=packet.dport, proto="UDP")
            session.udp[packet.dport] = probe
            self._probe_index[(packet.src, packet.dst, "UDP", packet.dport)] = probe

        probe.probes += 1
        probe.kinds.add("udp")
        probe.payload += packet.payload_len
        session.end = max(session.end, packet.ts)
        session.last_probe_ts = packet.ts
        self._syn_targets.setdefault((packet.src, packet.dport), set()).add(packet.dst)

    def _feed_icmp(self, packet: Packet) -> None:
        if packet.icmp_type in (_ICMP_ECHO_REQUEST, _ICMP_TIMESTAMP_REQUEST):
            self._echo.setdefault(packet.src, set()).add(packet.dst)
            return

        if packet.icmp_type != _ICMP_UNREACHABLE or not packet.inner_dport:
            return

        proto = {6: "TCP", 17: "UDP"}.get(packet.inner_proto)
        if proto is None:
            return
        probe = self._probe_index.get(
            (packet.inner_src, packet.inner_dst, proto, packet.inner_dport)
        )
        if probe is not None:
            probe.icmp_unreachable += 1

    # --------------------------------------------------------------- helpers

    @staticmethod
    def _is_response(packet: Packet) -> bool:
        if packet.flags & RST:
            return True
        if (packet.flags & SYN) and (packet.flags & ACK):
            return True
        if (packet.flags & SYN) and (packet.flags & FIN):
            return False
        return packet.payload_len > 0

    @staticmethod
    def _apply_response(probe: PortProbe, packet: Packet) -> None:
        if packet.flags & RST:
            probe.rst_from_target += 1
        if (packet.flags & SYN) and (packet.flags & ACK):
            probe.synack += 1

    def _mark_established(
        self, src: str, sport: int, dst: str, dport: int
    ) -> None:
        self._established.add((src, sport, dst, dport))
        self._established.add((dst, dport, src, sport))

    def _session_for(self, scanner: str, target: str, ts: float) -> ScanSession:
        key = (scanner, target)
        session = self._current.get(key)
        if session is None or ts - session.last_probe_ts > self.config.session_gap:
            session = ScanSession(
                scanner=scanner,
                target=target,
                start=ts,
                end=ts,
                last_probe_ts=ts,
            )
            self._current[key] = session
            self._sessions.append(session)
        return session

    # ---------------------------------------------------------------- finish

    def finish(self) -> Analysis:
        return Analysis(
            sessions=list(self._sessions),
            echo_targets={k: set(v) for k, v in self._echo.items()},
            syn_targets={k: set(v) for k, v in self._syn_targets.items()},
            first_ts=self._first or 0.0,
            last_ts=self._last,
        )

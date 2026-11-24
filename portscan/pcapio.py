"""Decode pcap/pcapng captures into flat :class:`Packet` records using DPKT."""

from __future__ import annotations

import os
import socket
import struct

import dpkt

from .models import Packet

# Link-layer types we know how to unwrap (``tcpdump -L`` / pcap-linktype(7)).
_DLT_NULL = 0
_DLT_EN10MB = 1
_DLT_RAW = 12
_DLT_LOOP = 108
_DLT_LINUX_SLL = 113
_DLT_IPV4 = 228
_DLT_IPV6 = 229
_DLT_LINUX_SLL2 = 276

_IPPROTO_TCP = 6
_IPPROTO_UDP = 17
_ICMP_ERROR_TYPES = (3, 4, 5, 11, 12)


class CaptureError(RuntimeError):
    """Raised when a capture file cannot be opened or decoded."""


def read_packets(path: str) -> tuple[list[Packet], int]:
    """Parse *path* and return ``(packets, skipped_frame_count)``.

    Frames that DPKT cannot decode (truncated snaplen, non-IP protocols) are
    counted and skipped instead of aborting the whole analysis, because real
    captures routinely contain ARP, STP and garbage frames.
    """
    if os.path.isdir(path):
        raise CaptureError(f"{path}: is a directory, not a capture file")
    try:
        handle = open(path, "rb")
    except OSError as exc:
        raise CaptureError(f"{path}: {exc.strerror or exc}") from exc

    with handle:
        magic = handle.read(4)
        handle.seek(0)
        try:
            reader = (
                dpkt.pcapng.Reader(handle)
                if magic == b"\x0a\x0d\x0d\x0a"
                else dpkt.pcap.Reader(handle)
            )
            linktype = reader.datalink()
        except (ValueError, struct.error, dpkt.dpkt.UnpackError) as exc:
            raise CaptureError(f"{path}: not a pcap/pcapng capture ({exc})") from exc

        packets: list[Packet] = []
        skipped = 0
        try:
            for ts, buf in reader:
                try:
                    packet = _decode(float(ts), buf, linktype)
                except Exception:  # one bad frame must not kill the run
                    skipped += 1
                    continue
                if packet is None:
                    skipped += 1
                else:
                    packets.append(packet)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, struct.error) as exc:
            raise CaptureError(f"{path}: truncated or corrupt capture ({exc})") from exc

    return packets, skipped


def _decode(ts: float, buf: bytes, linktype: int) -> Packet | None:
    ip = _network_layer(buf, linktype)
    if ip is None:
        return None
    return _decode_ip(ts, ip)


def _network_layer(buf: bytes, linktype: int):
    if linktype == _DLT_EN10MB:
        return dpkt.ethernet.Ethernet(buf).data
    if linktype in (_DLT_RAW, _DLT_IPV4, _DLT_IPV6):
        return _parse_ip(buf)
    if linktype in (_DLT_NULL, _DLT_LOOP):
        return dpkt.loopback.Loopback(buf).data
    if linktype == _DLT_LINUX_SLL:
        return dpkt.sll.SLL(buf).data
    if linktype == _DLT_LINUX_SLL2:
        sll2 = getattr(dpkt, "sll2", None)
        return sll2.SLL2(buf).data if sll2 is not None else None
    return None


def _parse_ip(buf: bytes):
    if not buf:
        return None
    return dpkt.ip6.IP6(buf) if buf[0] >> 4 == 6 else dpkt.ip.IP(buf)


def _decode_ip(ts: float, ip) -> Packet | None:
    if isinstance(ip, dpkt.ip.IP):
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
    elif isinstance(ip, dpkt.ip6.IP6):
        src = socket.inet_ntop(socket.AF_INET6, ip.src)
        dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
    else:
        return None

    if ip.p == _IPPROTO_TCP:
        tcp = ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            return None
        return Packet(
            ts=ts,
            src=src,
            dst=dst,
            proto="TCP",
            sport=tcp.sport,
            dport=tcp.dport,
            flags=tcp.flags,
            win=tcp.win,
            payload_len=len(tcp.data),
        )

    if ip.p == _IPPROTO_UDP:
        udp = ip.data
        if not isinstance(udp, dpkt.udp.UDP):
            return None
        return Packet(
            ts=ts,
            src=src,
            dst=dst,
            proto="UDP",
            sport=udp.sport,
            dport=udp.dport,
            payload_len=len(udp.data),
        )

    icmp = ip.data
    icmp6 = getattr(dpkt, "icmp6", None)
    if isinstance(icmp, dpkt.icmp.ICMP):
        packet = Packet(
            ts=ts,
            src=src,
            dst=dst,
            proto="ICMP",
            icmp_type=icmp.type,
            icmp_code=icmp.code,
        )
        _attach_quoted_packet(packet, icmp)
        return packet
    if icmp6 is not None and isinstance(icmp, icmp6.ICMP6):
        return Packet(
            ts=ts,
            src=src,
            dst=dst,
            proto="ICMP",
            icmp_type=icmp.type,
            icmp_code=icmp.code,
        )
    return None


def _attach_quoted_packet(packet: Packet, icmp) -> None:
    """Fill ``inner_*`` from the IP header quoted inside an ICMP error message."""
    inner = getattr(getattr(icmp, "data", None), "ip", None)
    if inner is None and icmp.type in _ICMP_ERROR_TYPES:
        try:
            inner = dpkt.ip.IP(bytes(icmp.data))
        except Exception:
            inner = None
    if not isinstance(inner, dpkt.ip.IP):
        return

    packet.inner_src = socket.inet_ntoa(inner.src)
    packet.inner_dst = socket.inet_ntoa(inner.dst)
    packet.inner_proto = inner.p
    if inner.p == _IPPROTO_TCP and isinstance(inner.data, dpkt.tcp.TCP):
        packet.inner_sport = inner.data.sport
        packet.inner_dport = inner.data.dport
    elif inner.p == _IPPROTO_UDP and isinstance(inner.data, dpkt.udp.UDP):
        packet.inner_sport = inner.data.sport
        packet.inner_dport = inner.data.dport

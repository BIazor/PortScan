"""Classification of individual TCP segments as Nmap-style probes.

Nmap's stateless scan techniques are distinguishable because each one emits a
different TCP flag combination, and none of them complete a normal connection:

===============  ==========================  =============================
technique        flag byte                   closed-port response
===============  ==========================  =============================
``-sS``          SYN                         RST+ACK
``-sT``          SYN (then ACK)              RST+ACK / full handshake
``-sF``          FIN                         RST+ACK
``-sX``          FIN+PSH+URG                 RST+ACK
``-sN``          none (0x00)                 RST+ACK
``-sA``          ACK                         RST+ACK
``-sM``          FIN+ACK                     RST+ACK
``-sO`` (OS)     SYN+FIN, SYN+RST, ...       RST / SYN+ACK
===============  ==========================  =============================

Anything that belongs to an established connection (a FIN+ACK closing a real
session, an ACK acknowledging data) must *not* be reported as a probe, which is
why :func:`classify_probe` takes the connection state as an argument.
"""

from __future__ import annotations

from .models import ACK, CWR, ECE, FIN, PSH, RST, SYN, URG

# Probe kinds understood by the detectors.
KIND_SYN = "syn"
KIND_FIN = "fin"
KIND_XMAS = "xmas"
KIND_NULL = "null"
KIND_ACK = "ack"
KIND_MAIMON = "maimon"
KIND_ANOMALY = "anomaly"
KIND_FIN_VARIANT = "fin_variant"

PROBE_TITLES = {
    KIND_SYN: "SYN",
    KIND_FIN: "FIN",
    KIND_XMAS: "FIN+PSH+URG (XMAS)",
    KIND_NULL: "no flags (NULL)",
    KIND_ACK: "ACK",
    KIND_MAIMON: "FIN+ACK (Maimon)",
    KIND_ANOMALY: "malformed flag combination",
    KIND_FIN_VARIANT: "FIN without ACK",
}


def classify_probe(flags: int, *, prior_handshake: bool = False) -> str | None:
    """Return the probe kind for a TCP flag byte, or ``None`` if it is not a probe.

    ``prior_handshake`` is True when the 4-tuple already carried a completed
    three-way handshake in the capture; such a segment is connection
    maintenance, not reconnaissance.
    """
    if flags & SYN:
        if flags & ACK:
            return None  # SYN+ACK is the responder's half of a handshake
        if flags & FIN:
            return KIND_ANOMALY  # SYN+FIN is emitted by nmap's OS detection
        if flags & RST:
            return KIND_ANOMALY  # SYN+RST likewise
        if flags == SYN:
            return KIND_SYN
        if flags & (ECE | CWR):
            return KIND_ANOMALY  # explicit-congestion-notification probe
        return KIND_ANOMALY  # SYN+PSH, SYN+URG, ...
    if flags == 0:
        return KIND_NULL
    if flags & RST:
        return None  # a reset is always a response, never a probe
    if flags == FIN:
        return KIND_FIN
    if flags == (FIN | PSH | URG):
        return KIND_XMAS
    if flags == (FIN | ACK):
        return None if prior_handshake else KIND_MAIMON
    if flags == ACK:
        return None if prior_handshake else KIND_ACK
    if (flags & FIN) and not (flags & ACK) and not prior_handshake:
        return KIND_FIN_VARIANT  # e.g. FIN+URG
    return None

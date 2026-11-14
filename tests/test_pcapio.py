"""Parser and probe-classifier unit tests."""

from __future__ import annotations

import pytest

from scanwatch.models import ACK, FIN, PSH, RST, SYN, URG
from scanwatch.pcapio import CaptureError, read_packets
from scanwatch.probes import classify_probe


def test_classify_probe_maps_nmap_flag_combinations():
    assert classify_probe(SYN) == "syn"
    assert classify_probe(FIN) == "fin"
    assert classify_probe(FIN | PSH | URG) == "xmas"
    assert classify_probe(0) == "null"
    assert classify_probe(ACK) == "ack"
    assert classify_probe(FIN | ACK) == "maimon"
    assert classify_probe(SYN | FIN) == "anomaly"
    assert classify_probe(SYN | RST) == "anomaly"


def test_responses_are_never_probes():
    assert classify_probe(SYN | ACK) is None
    assert classify_probe(RST) is None
    assert classify_probe(RST | ACK) is None
    # A normal connection close (FIN+ACK) must not look like a Maimon scan.
    assert classify_probe(FIN | ACK, prior_handshake=True) is None
    assert classify_probe(ACK, prior_handshake=True) is None


def test_missing_file_raises_capture_error(tmp_path):
    with pytest.raises(CaptureError):
        read_packets(str(tmp_path / "does-not-exist.pcap"))


def test_non_pcap_file_raises_capture_error(tmp_path):
    path = tmp_path / "notes.pcap"
    path.write_bytes(b"this is definitely not a packet capture")
    with pytest.raises(CaptureError):
        read_packets(str(path))


def test_reads_dlt_null_loopback_capture(tmp_path):
    """Npcap's loopback adapter writes DLT_NULL frames, not Ethernet ones."""
    import struct

    import dpkt

    tcp = dpkt.tcp.TCP(sport=40000, dport=445, flags=dpkt.tcp.TH_SYN, win=1024)
    ip = dpkt.ip.IP(
        src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02", p=6, data=tcp
    )
    frame = struct.pack("<I", 2) + ip.pack()  # AF_INET + IP packet

    path = tmp_path / "loopback.pcap"
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 0))
        handle.write(struct.pack("<IIII", 1, 0, len(frame), len(frame)))
        handle.write(frame)

    packets, skipped = read_packets(str(path))

    assert skipped == 0
    assert len(packets) == 1
    assert packets[0].src == "10.0.0.1"
    assert packets[0].dport == 445
    assert packets[0].flags & SYN


def test_undecodable_frames_are_counted_not_fatal(tmp_path):
    import dpkt

    from scanwatch.synth import write_scenario

    good = tmp_path / "good.pcap"
    write_scenario("benign_dns", good)
    before = len(good.read_bytes())

    # Append a frame that is not parsable as Ethernet/IP.
    bogus = b"\xff" * 16
    header_tail = b"".join(
        [
            b"\x00\x00\x00\x00",  # ts_sec
            b"\x00\x00\x00\x00",  # ts_usec
            len(bogus).to_bytes(4, "little"),
            len(bogus).to_bytes(4, "little"),
        ]
    )
    with open(good, "ab") as handle:
        handle.write(header_tail + bogus)

    packets, skipped = read_packets(str(good))
    assert packets
    assert skipped == 1
    assert len(good.read_bytes()) > before

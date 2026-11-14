"""Minimal live capture through Npcap's ``wpcap.dll`` (Windows only).

The Nmap validation lab needs a capture driver but not a full packet stack:
Wireshark/tshark is often absent on a machine that already has Nmap, because
Nmap bundles Npcap. This module binds the handful of libpcap entry points the
lab needs and reads frames on a background thread.
"""

from __future__ import annotations

import ctypes
import os
import socket
import threading
from dataclasses import dataclass, field
from ctypes import (
    POINTER,
    c_char_p,
    c_int,
    c_ubyte,
    c_uint,
    c_uint32,
    c_ulong,
    c_ushort,
    c_void_p,
)

PCAP_ERRBUF_SIZE = 256
DLT_EN10MB = 1


class NpcapError(RuntimeError):
    """Raised when Npcap is missing or refuses the capture."""


# ----------------------------------------------------------------- structs


class _Timeval(ctypes.Structure):
    # Windows ``long`` is 32 bits, so timeval is 8 bytes like on WinPcap.
    _fields_ = [("tv_sec", c_ulong), ("tv_usec", c_ulong)]


class _PcapPkthdr(ctypes.Structure):
    _fields_ = [("ts", _Timeval), ("caplen", c_uint32), ("len", c_uint32)]


class _PcapAddr(ctypes.Structure):
    pass


class _PcapIf(ctypes.Structure):
    pass


_PcapAddr._fields_ = [
    ("next", POINTER(_PcapAddr)),
    ("addr", c_void_p),
    ("netmask", c_void_p),
    ("broadaddr", c_void_p),
    ("dstaddr", c_void_p),
]

_PcapIf._fields_ = [
    ("next", POINTER(_PcapIf)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", POINTER(_PcapAddr)),
    ("flags", c_uint),
]


class _Sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", c_ushort), ("sa_data", c_ubyte * 14)]


class _BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", c_uint), ("bf_insns", c_void_p)]


# ------------------------------------------------------------------ loader

_library_lock = threading.Lock()
_library: ctypes.WinDLL | None = None


def _load() -> ctypes.WinDLL:
    global _library
    with _library_lock:
        if _library is not None:
            return _library
        if os.name != "nt":
            raise NpcapError(
                "live capture is implemented for Windows/Npcap; "
                "analyze a saved pcap on this platform instead"
            )
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        candidates = [
            os.path.join(system_root, "System32", "Npcap", "wpcap.dll"),
            os.path.join(system_root, "System32", "wpcap.dll"),
            r"C:\Program Files (x86)\Nmap\wpcap.dll",
        ]
        last_error = None
        for path in candidates:
            if os.path.exists(path):
                try:
                    _library = ctypes.WinDLL(path)
                    break
                except OSError as exc:  # pragma: no cover - platform specific
                    last_error = exc
        if _library is None:
            raise NpcapError(
                "wpcap.dll not found - install Npcap (it ships with the Nmap "
                "Windows installer) to capture live traffic"
            ) from last_error
        _bind(_library)
        return _library


def _bind(lib: ctypes.WinDLL) -> None:
    lib.pcap_findalldevs.argtypes = [POINTER(POINTER(_PcapIf)), c_char_p]
    lib.pcap_findalldevs.restype = c_int
    lib.pcap_freealldevs.argtypes = [POINTER(_PcapIf)]
    lib.pcap_freealldevs.restype = None
    lib.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
    lib.pcap_open_live.restype = c_void_p
    lib.pcap_close.argtypes = [c_void_p]
    lib.pcap_close.restype = None
    lib.pcap_datalink.argtypes = [c_void_p]
    lib.pcap_datalink.restype = c_int
    lib.pcap_compile.argtypes = [
        c_void_p,
        POINTER(_BpfProgram),
        c_char_p,
        c_int,
        c_uint32,
    ]
    lib.pcap_compile.restype = c_int
    lib.pcap_freecode.argtypes = [POINTER(_BpfProgram)]
    lib.pcap_freecode.restype = None
    lib.pcap_setfilter.argtypes = [c_void_p, POINTER(_BpfProgram)]
    lib.pcap_setfilter.restype = c_int
    lib.pcap_next_ex.argtypes = [
        c_void_p,
        POINTER(POINTER(_PcapPkthdr)),
        POINTER(POINTER(c_ubyte)),
    ]
    lib.pcap_next_ex.restype = c_int
    lib.pcap_breakloop.argtypes = [c_void_p]
    lib.pcap_breakloop.restype = None
    lib.pcap_geterr.argtypes = [c_void_p]
    lib.pcap_geterr.restype = c_char_p


# ----------------------------------------------------------------- devices


@dataclass
class Device:
    name: str
    description: str
    addresses: list[str]


def list_devices() -> list[Device]:
    lib = _load()
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    alldevs = POINTER(_PcapIf)()
    if lib.pcap_findalldevs(ctypes.byref(alldevs), errbuf) != 0:
        raise NpcapError(errbuf.value.decode(errors="replace"))

    devices: list[Device] = []
    node = alldevs
    while node:
        entry = node.contents
        addresses: list[str] = []
        address = entry.addresses
        while address:
            sockaddr_ptr = address.contents.addr
            if sockaddr_ptr:
                sockaddr = ctypes.cast(sockaddr_ptr, POINTER(_Sockaddr)).contents
                if sockaddr.sa_family == socket.AF_INET:
                    addresses.append(socket.inet_ntoa(bytes(sockaddr.sa_data[2:6])))
            address = address.contents.next
        devices.append(
            Device(
                name=entry.name.decode(errors="replace"),
                description=(entry.description or b"").decode(errors="replace"),
                addresses=addresses,
            )
        )
        node = entry.next

    lib.pcap_freealldevs(alldevs)
    return devices


def find_device_for_ip(ip: str) -> str:
    """Return the Npcap device that owns *ip* (falls back to the loopback adapter)."""
    devices = list_devices()
    for device in devices:
        if ip in device.addresses:
            return device.name
    for device in devices:
        haystack = f"{device.name} {device.description}".lower()
        if "loopback" in haystack or "npf_loopback" in haystack:
            return device.name
    available = "\n".join(f"  {d.name}  {d.description} {d.addresses}" for d in devices)
    raise NpcapError(f"no capture device for {ip}; available devices:\n{available}")


# ---------------------------------------------------------------- capturing


@dataclass
class Capture:
    device: str
    snaplen: int = 65535
    filter: str = "tcp or udp or icmp"
    linktype: int = -1
    frames: list[tuple[float, bytes]] = field(default_factory=list)
    error: str = ""
    _lib: ctypes.WinDLL | None = field(default=None, repr=False)
    _handle: c_void_p | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)

    def start(self) -> None:
        lib = _load()
        self._lib = lib
        errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        handle = lib.pcap_open_live(
            self.device.encode(), self.snaplen, 0, 100, errbuf
        )
        if not handle:
            raise NpcapError(errbuf.value.decode(errors="replace"))
        self._handle = handle
        self.linktype = lib.pcap_datalink(handle)

        if self.filter:
            program = _BpfProgram()
            if (
                lib.pcap_compile(
                    handle,
                    ctypes.byref(program),
                    self.filter.encode(),
                    1,
                    0xFFFFFF00,
                )
                != 0
            ):
                self._raise(handle, "cannot compile capture filter")
            if lib.pcap_setfilter(handle, ctypes.byref(program)) != 0:
                self._raise(handle, "cannot install capture filter")
            lib.pcap_freecode(ctypes.byref(program))

        self._stop.clear()
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()

    def _raise(self, handle, message: str) -> None:
        assert self._lib is not None
        detail = self._lib.pcap_geterr(handle)
        self.close()
        raise NpcapError(f"{message}: {detail.decode(errors='replace') if detail else 'unknown error'}")

    def _read_loop(self) -> None:
        assert self._lib is not None and self._handle is not None
        header = POINTER(_PcapPkthdr)()
        data = POINTER(c_ubyte)()
        while not self._stop.is_set():
            result = self._lib.pcap_next_ex(
                self._handle, ctypes.byref(header), ctypes.byref(data)
            )
            if result == 1:
                record = header.contents
                timestamp = record.ts.tv_sec + record.ts.tv_usec / 1_000_000
                self.frames.append(
                    (float(timestamp), ctypes.string_at(data, record.caplen))
                )
            elif result == 0:
                continue
            elif result == -2:
                break
            else:
                detail = self._lib.pcap_geterr(self._handle)
                self.error = (
                    detail.decode(errors="replace") if detail else "capture read error"
                )
                break

    def stop(self) -> list[tuple[float, bytes]]:
        self._stop.set()
        if self._lib is not None and self._handle:
            self._lib.pcap_breakloop(self._handle)
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.close()
        if self.error:
            raise NpcapError(self.error)
        return self.frames

    def close(self) -> None:
        if self._lib is not None and self._handle:
            self._lib.pcap_close(self._handle)
            self._handle = None


def write_pcap(path, frames: list[tuple[float, bytes]], linktype: int = DLT_EN10MB):
    """Persist captured frames as a classic pcap file, preserving *linktype*.

    The header is written by hand because ``dpkt.pcap.Writer`` hardcodes
    Ethernet, while Npcap's loopback adapter reports ``DLT_NULL``.
    """
    import struct

    with open(path, "wb") as handle:
        handle.write(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
        )
        for timestamp, frame in frames:
            seconds = int(timestamp)
            micros = int(round((timestamp - seconds) * 1_000_000))
            if micros >= 1_000_000:
                seconds += 1
                micros -= 1_000_000
            handle.write(
                struct.pack("<IIII", seconds, micros, len(frame), len(frame))
            )
            handle.write(frame)

"""portscan - detect Nmap reconnaissance techniques in packet captures."""

from .detectors import DetectionConfig, detect
from .models import Finding, Packet, PortProbe, ScanSession
from .pcapio import CaptureError, read_packets
from .tracker import ActivityTracker, Analysis, TrackerConfig

__version__ = "1.0.0"

__all__ = [
    "Analysis",
    "ActivityTracker",
    "CaptureError",
    "DetectionConfig",
    "Finding",
    "Packet",
    "PortProbe",
    "ScanSession",
    "TrackerConfig",
    "detect",
    "read_packets",
    "__version__",
]

# scanwatch

PCAP analysis tool that detects **network reconnaissance** — specifically Nmap port
scans — using **DPKT** for packet decoding and TCP flag / handshake analysis for
classification.

It answers one question well: *given a capture, which Nmap scan techniques were
used, against whom, and what is the packet-level evidence?*

```
$ python -m scanwatch analyze captures/real/syn_scan.pcap
scanwatch - network reconnaissance report
capture : captures/real/syn_scan.pcap
traffic : 825 packets (TCP 825, UDP 0, ICMP 0) in 0.14s

1 finding(s)

 1. [HIGH  ] TCP SYN scan (nmap -sS)   confidence 0.99
    scanner : 127.0.0.1
    target  : 127.0.0.1
    window  : 2026-11-12 19:58:50 -> 2026-11-12 19:58:50 (0.14s)
    ports   : 408
    evidence:
      - 408/408 TCP probes carried a bare SYN and never completed a handshake
      - 407/408 probes drew a response (9 SYN+ACK, 398 RST)
      - constant TCP window 1024 on every SYN (Nmap's default)
      - fan-out rate 2979 probes/s over 0.14s
```

## What it detects

| Technique | Nmap flag | Packet signature used | Evidence produced |
|---|---|---|---|
| TCP SYN scan | `-sS` | bare `SYN` to many ports, handshake never completed | SYN count, RST/SYN+ACK ratio, constant 1024 window |
| TCP connect scan | `-sT` | completed 3-way handshakes, closed without data | listening ports, handshake/close sequence |
| TCP FIN scan | `-sF` | `FIN` with no ACK to ports with no connection | RST responses, port list |
| TCP XMAS scan | `-sX` | `FIN+PSH+URG` | "Christmas tree" flag evidence |
| TCP NULL scan | `-sN` | flag byte `0x00` | zero-flag segments |
| TCP ACK scan | `-sA` | `ACK` only, no prior handshake | ACK segment count, RST replies |
| TCP Maimon scan | `-sM` | `FIN+ACK`, no prior handshake | FIN+ACK segments |
| UDP scan | `-sU` | UDP datagrams to many ports | ICMP port-unreachable attribution |
| Service/version detection | `-sV` | application data after a completed handshake on 3+ ports | probe byte/segment counts |
| OS fingerprinting | `-O` | illegal combinations (`SYN+FIN`, `SYN+RST`, ECN probes) | flag combinations observed |
| Host discovery sweep | `-sn` | ICMP echo/timestamp to many hosts | host count and sample |
| Horizontal port sweep | — | one port probed across many hosts | port, host count, sample |

Each finding carries a `confidence` (evidence volume × signature purity × target
responsiveness) and a `severity` derived from how many ports/hosts were touched.

## How it works

```
pcap/pcapng ──► pcapio ──► tracker ──► detectors ──► report
                (DPKT)     (sessions)   (rules)       (text/JSON)
```

1. **`scanwatch/pcapio.py`** decodes Ethernet, Linux SLL/SLL2, BSD loopback,
   raw IP and VLAN-tagged frames into flat `Packet` records. Bad frames are
   counted and skipped, not fatal.
2. **`scanwatch/tracker.py`** builds per-`(scanner, target)` **scan sessions**,
   split by idle gaps, and tracks state per probed port: SYN/SYN+ACK, completed
   handshakes, RSTs from each side, scanner payload, and ICMP unreachables.
   Separating probes from responses (and from legitimate connection teardown)
   is what keeps normal traffic from looking like a scan.
3. **`scanwatch/detectors.py`** applies one rule per technique, then merges
   repeated detections of the same flow.
4. **`scanwatch/report.py` / `cli.py`** render text or JSON.

## Install

```bash
pip install -r requirements.txt      # dpkt
# or install the package and its `scanwatch` command
pip install -e .
# optional, for the tests
pip install pytest
```

Analysis is pure Python and cross-platform. The live validation lab (below)
needs **Windows + Npcap**, which ships with the Nmap Windows installer.

## Usage

```bash
# analyse one or more captures
python -m scanwatch analyze capture.pcap
python -m scanwatch analyze captures/real/*.pcap
python -m scanwatch analyze capture.pcapng --json
python -m scanwatch analyze capture.pcap --fail-on-findings   # exit 1 when detections exist

# tune the rules
python -m scanwatch analyze capture.pcap --min-ports 30 --session-gap 60
```

| Option | Default | Meaning |
|---|---|---|
| `--min-ports` | 15 | distinct ports required for a port-scan finding |
| `--min-hosts` | 5 | distinct hosts required for a sweep finding |
| `--min-connect-ports` | 3 | completed handshakes required to call `-sT` |
| `--min-version-ports` | 3 | ports with post-handshake data required for `-sV` |
| `--min-udp-ports` | 25 | distinct ports required for `-sU` |
| `--session-gap` | 30 s | idle gap that starts a new scan session |

JSON findings contain `technique`, `severity`, `confidence`, `scanner`, `target`,
`ports`, `sessions`, `start`, `end` and the `evidence` lines.

## Validating with real Nmap traffic

`tools/nmap_lab.py` runs actual Nmap scans against **this host**, captures them
with Npcap, saves each capture, analyses it, and compares the result with the
expected technique:

```bash
python tools/nmap_lab.py                  # full run, default target 127.0.0.1
python tools/nmap_lab.py --only syn_scan  # one scenario
```

It opens eight fake services on ports 20001–20008 so that `-sT`, `-sV` and the
open-port branches of `-sS` have something real to talk to. The services emit a
banner Nmap cannot identify, so `-sV` actually sends its probe payloads instead
of short-circuiting on a recognised banner.

Outputs:

```
captures/real/<scenario>.pcap       the raw capture
captures/real/<scenario>.nmap.txt   the exact nmap command and its output
captures/real/validation.json       expected vs detected, per scenario
```

Measured with Nmap 7.98 (Npcap 1.87, Windows loopback), full run:

| Scenario | Expected | Detected | Verdict |
|---|---|---|---|
| `syn_scan` | syn | syn | PASS |
| `connect_scan` | connect | connect | PASS |
| `fin_scan` | fin | fin | PASS |
| `xmas_scan` | xmas | xmas | PASS |
| `null_scan` | null | null | PASS |
| `ack_scan` | ack | ack | PASS |
| `maimon_scan` | maimon | maimon | PASS |
| `udp_scan` | udp | udp | PASS |
| `version_scan` | version | version | PASS |
| `os_fingerprint` | syn + os_fingerprint | syn + os_fingerprint | PASS |

**10/10 scenarios, 100% technique recall, 100% precision (11/11 expected
techniques, 0 extra findings).** `-O` legitimately produces both a SYN port
scan and fingerprint probes, so both are expected.

## Offline fixtures

`python -m scanwatch synth samples` writes 15 labelled captures that reproduce
Nmap's wire signatures (including two benign traffic captures that must produce
no findings), plus `samples/labels.json`. These are **synthetic**; they exist so
the detector can be tested on machines without Nmap or a capture driver. The
real-traffic numbers above come from the lab, not from these files.

## Tests

```bash
python -m pytest
```

25 tests: one end-to-end detection assertion per labelled capture (including
false-positive guards for HTTP, DNS and UDP service-discovery traffic), parser
tests for pcap and
`DLT_NULL` loopback captures, truncated-frame handling, and TCP flag
classification tests.

## Limitations

- **`-sS` vs `-sT` on a host with no open ports.** A connect scan to closed
  ports produces bare SYNs and RSTs, exactly like a SYN scan. Completed
  handshakes are the only distinguishing evidence, so with fewer than
  `--min-connect-ports` open ports a connect scan is reported as a SYN scan.
- **Single-port `-sV`** looks like a client talking to one service and is not
  flagged; version detection requires probes across 3+ ports.
- **UDP scans** are detected by port fan-out. ICMP rate limiting can hide the
  port-unreachable replies, which lowers confidence but not detection. The bar
  is 25 distinct ports: shorter bursts (service discovery, mDNS-style chatter)
  are not flagged. Real `-sU` runs touch hundreds of ports, so this leaves a
  wide margin; lower `--min-udp-ports` if you need to catch tiny sweeps.
- **`-O`** is detected from illegal flag combinations; a stack that answers only
  the well-formed fingerprint probes may not be identified.
- **Not implemented:** idle scan (`-sI`), decoys (`-D`), fragmentation (`-f`,
  `--mtu`), IP-ID analysis, and application-layer parsing.
- **IPv4 first.** IPv6 packets are parsed, but ICMPv6 quoted packets are not used
  for UDP/TCP response attribution.
- **Lab scope.** All accuracy figures are from loopback captures of Nmap traffic
  and synthetic fixtures. On a switched production network you may only see one
  direction of a scan, which lowers evidential confidence (reported explicitly in
  the finding as "scan may be filtered or captured one-way").
- The lab's live-capture path is Windows/Npcap only; the analyzer itself runs
  anywhere Python and DPKT do.

## Project layout

```
scanwatch/
  pcapio.py      DPKT capture decoding (pcap, pcapng, Ethernet/SLL/loopback)
  tracker.py     per-(scanner,target) sessions, handshake and response state
  probes.py      TCP flag byte -> Nmap probe kind
  detectors.py   one rule per technique + confidence/severity scoring
  report.py      text and JSON rendering
  cli.py         analyze / synth commands
  synth.py       labelled synthetic Nmap captures
tools/
  npcap_capture.py  ctypes binding for Npcap live capture
  nmap_lab.py       generate real Nmap traffic and score the detector
samples/           15 synthetic labelled captures + labels.json
captures/real/     real Nmap captures, nmap logs, validation.json
tests/
```

## Legal

Use only against hosts you own or are explicitly authorised to test. The lab
refuses any target that is not loopback or RFC1918-private.

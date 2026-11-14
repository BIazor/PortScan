# scanwatch

A small Python tool that reads a packet capture (a `.pcap` file, meaning a
recording of network traffic) and tells you whether someone was **probing your
network for open ports**.

When an attacker (or a pentester, or a curious admin) wants in, the first thing
they usually do is knock on lots of doors to see which ones are unlocked. That
is called **reconnaissance**, and the most common way to do it is a **port
scan**, usually with a tool called [Nmap](https://nmap.org). A port scan sends
slightly unusual packets to hundreds of ports on one or many machines, and those
packets leave a pattern behind.

scanwatch finds those patterns. You give it a capture, and it tells you which
Nmap scan technique was used, who was scanning whom, and which packets gave it
away.

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

Notice the last block. "408 SYN packets, none of them finished a connection"
is not a guess. It is a specific, checkable fact about the traffic, and that is
what the verdict is built on.

## Why I built it

I am fairly new to security and I learn best by taking things apart. Nmap is a
tool everyone tells you to run, but far fewer people can explain what its
packets actually look like on the wire, or how you would spot them if you were
on the defending side. So I wrote my own detector, then pointed real Nmap at a
machine, captured the traffic, and checked that my detector got the answer
right. That comparison, expecting a technique and then seeing the tool name it
correctly, is the part I care most about, and it is in the repo as a script
you can re-run yourself.

## Background, if you are new to this

Feel free to skip this section if you already know TCP.

- **TCP** is the protocol behind most traffic you care about (web, SSH, email).
  It starts every conversation with a three-step greeting called the
  **handshake**: your machine sends `SYN` ("can we talk?"), the server replies
  `SYN+ACK` ("yes, go ahead"), and you send `ACK` ("great, talking now").
- If the port is closed, the server replies `RST` instead ("no, go away").
  So `SYN` followed by `RST` means *closed*, and `SYN` followed by `SYN+ACK`
  means *open*. That is the whole basis of port scanning.
- A normal client completes the handshake and then says something useful. A
  scanner often sends the first packet and then immediately walks away, or
  deliberately sends packets in weird combinations (`FIN`, `PSH+URG`, no flags
  at all) that a normal program would never send.
- **pcap** is just a file format for recorded packets. Wireshark and tcpdump
  read and write it.

Different Nmap flags produce different packets. That is why one detector can
tell them apart: it is not guessing from timing, it is reading the flags.

## What it detects

| Technique | Nmap flag | What the packets look like | What scanwatch reports |
|---|---|---|---|
| TCP SYN scan | `-sS` | bare `SYN` to many ports, handshake never finishes | SYN count, how many got RST vs SYN+ACK, the constant 1024 window |
| TCP connect scan | `-sT` | full handshakes, then closed without sending data | which ports were open, the handshake-then-close pattern |
| TCP FIN scan | `-sF` | `FIN` with no `ACK`, no connection ever started | RST replies, port list |
| TCP XMAS scan | `-sX` | `FIN+PSH+URG` set together (hence "Christmas tree") | the flag combination |
| TCP NULL scan | `-sN` | no flags at all (flag byte `0x00`) | zero-flag segments |
| TCP ACK scan | `-sA` | `ACK` only, with no handshake before it | ACK count, RST replies |
| TCP Maimon scan | `-sM` | `FIN+ACK`, again with no handshake first | FIN+ACK segments |
| UDP scan | `-sU` | UDP datagrams fired at many ports | which ICMP "port unreachable" replies came back |
| Version detection | `-sV` | sends real application data after connecting, on several ports | how many ports got probe data |
| OS fingerprinting | `-O` | deliberately invalid flag combos (`SYN+FIN`, `SYN+RST`, odd ECN packets) | the exact combos seen |
| Host sweep | `-sn` | ICMP echo/timestamp to many machines | how many hosts, and which |
| Horizontal sweep | n/a | the *same* port probed across many machines | the port, host count, samples |

Every finding comes with a `confidence` score (how much evidence there is, how
clean the pattern is, and whether the target answered at all) and a `severity`
based on how many ports or hosts were involved. A scan of 400 ports reads very
differently from a scan of 20.

## How it works

```
pcap/pcapng ──► pcapio ──► tracker ──► detectors ──► report
                (DPKT)     (sessions)   (rules)       (text/JSON)
```

1. **`scanwatch/pcapio.py`** opens the capture with DPKT and turns each frame
   into a plain, flat record. It handles the usual link layers so you do not
   need to care whether the capture came from Ethernet, a Linux `any`
   interface, a BSD loopback or a VLAN. Damaged frames are counted and skipped
   rather than crashing the run.
2. **`scanwatch/tracker.py`** is where most of the thinking happens. It groups
   traffic into sessions per (scanner, target) pair, splits them when there is a
   long idle gap, and keeps per-port state: did we see `SYN`, did we see a
   `SYN+ACK`, did the handshake finish, did someone send `RST`, did the scanner
   send data afterwards. Keeping *probes* separate from *responses* is the whole
   trick: it is what stops normal web browsing from looking like a scan.
3. **`scanwatch/detectors.py`** holds one small rule per technique and merges
   duplicate hits for the same flow into a single finding.
4. **`scanwatch/report.py`** and **`cli.py`** print the result, either as nicely
   formatted text or as JSON for other tools.

## Install

```bash
pip install -r requirements.txt      # dpkt
# or install the package and get a `scanwatch` command
pip install -e .
# optional, only needed for the tests
pip install pytest
```

Analysing captures is pure Python, so it works on Windows, macOS and Linux.

Running the live lab (further down) is a different story: it captures packets
from the machine it runs on, which on Windows means **Npcap**. That ships with
the Nmap Windows installer, so installing Nmap usually gets you both.

## Usage

```bash
# one capture
python -m scanwatch analyze capture.pcap

# several at once, prints a report per file
python -m scanwatch analyze captures/real/*.pcap

# machine-readable output
python -m scanwatch analyze capture.pcapng --json

# exit code 1 if anything was found, handy in a script or CI job
python -m scanwatch analyze capture.pcap --fail-on-findings

# make the rules stricter or looser
python -m scanwatch analyze capture.pcap --min-ports 30 --session-gap 60
```

| Option | Default | What it does |
|---|---|---|
| `--min-ports` | 15 | how many different ports before we call it a port scan |
| `--min-hosts` | 5 | how many different hosts before we call it a sweep |
| `--min-connect-ports` | 3 | completed handshakes needed to call something `-sT` |
| `--min-version-ports` | 3 | ports that must receive app data to call something `-sV` |
| `--min-udp-ports` | 25 | how many UDP ports before we call it `-sU` |
| `--session-gap` | 30 s | a pause this long starts a new scan session |

The JSON output contains `title`, `technique`, `severity`, `confidence`,
`scanner`, `target`, `ports`, `sessions`, `start`, `end` and the `evidence`
lines, the same information as the text report.

## Checking it against real Nmap traffic

This is the part I would want to see if I were reading someone else's project.
`tools/nmap_lab.py` does not fake anything: it runs **real Nmap** against this
machine, captures the traffic with Npcap, analyses the capture, and compares the
result against the technique it asked Nmap to perform.

```bash
python tools/nmap_lab.py                  # all scenarios, target 127.0.0.1
python tools/nmap_lab.py --only syn_scan  # just one
```

To give the scans something to find, the script starts eight small fake
services on ports 20001–20008. That matters for `-sT` (cancel scans need open
ports to connect to) and for `-sV` (version detection has to have something to
talk to). The fake services reply with a banner Nmap cannot identify, which
keeps it probing and actually sending its payload. With a real-looking SSH or
HTTP banner, Nmap recognises the service immediately and sends nothing, and the
test ends up proving very little.

It writes:

```
captures/real/<scenario>.pcap       the raw capture
captures/real/<scenario>.nmap.txt   the exact nmap command and its output
captures/real/validation.json       expected vs detected, per scenario
```

Results from a full run (Nmap 7.98, Npcap 1.87, Windows loopback):

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

That is **10/10 scenarios, 100% of the expected techniques found, and 0 extra
findings**. The two-technique row is not a mistake: `-O` really does perform a
SYN scan first and then start fingerprinting, so both answers are correct.

Worth saying plainly: these are loopback captures on one machine. It is a
controlled test, not a live network, and the limitations section below covers
where that matters.

## Ready-made sample captures

If you do not have Nmap installed, or cannot capture packets on your machine,
there are samples:

```bash
python -m scanwatch synth samples
```

This writes 15 labelled captures that reproduce the same packet signatures,
plus `samples/labels.json` telling you what each one should produce. Three of
them are ordinary traffic (a web session, DNS lookups and some UDP service
discovery) and should produce **no** findings at all. Those exist to catch a
detector that flags everything.

These files are **synthetic**. They are convenient for testing on any machine,
but the accuracy numbers above came from the real Nmap lab, not from them.

## Tests

```bash
python -m pytest
```

25 tests: one end-to-end assertion per labelled sample (including the
false-positive guards for HTTP, DNS and UDP discovery traffic), parser tests for
pcap files and loopback (`DLT_NULL`) captures, handling of truncated frames, and
tests for the TCP flag classification itself.

## Limitations

I would rather list these than have someone find them the hard way.

- **A connect scan against a host with no open ports looks exactly like a SYN
  scan.** Both send a bare `SYN` and get `RST` back. The only way to tell them
  apart is a completed handshake, so if fewer than `--min-connect-ports` ports
  are open, a `-sT` scan gets reported as `-sS`. This is the honest weak spot.
- **Version detection against a single port** looks like a normal client talking
  to one service, so it is not flagged. It takes probes to 3+ ports.
- **UDP scanning** is judged by how many ports get hit. That bar is 25, because
  ordinary background traffic (service discovery, mDNS-style chatter) produces
  short bursts that should not be called an attack. I saw exactly that happen
  during testing at a threshold of 10. Real `-sU` runs touch hundreds of ports,
  so there is plenty of margin; lower `--min-udp-ports` if you need to catch
  tiny sweeps and can tolerate more noise.
- **OS fingerprinting** is spotted from the invalid flag combinations it sends.
  A hardened stack that quietly drops those probes will not be identified.
- **Not implemented:** idle scans (`-sI`), decoys (`-D`), fragmentation
  (`-f`/`--mtu`), IP-ID analysis, and any application-layer parsing.
- **IPv4 comes first.** IPv6 packets are decoded, but ICMPv6 replies are not
  used to attribute UDP/TCP responses yet.
- **One direction only.** On a switched network you may only see the scanner's
  side of the conversation. The tool still reports the finding but lowers
  confidence and says so in the evidence ("scan may be filtered or captured
  one-way").
- **The live lab is Windows/Npcap only.** The analyser itself is not.

## Project layout

```
scanwatch/
  pcapio.py      capture decoding: pcap, pcapng, Ethernet/SLL/loopback (DPKT)
  tracker.py     per-(scanner,target) sessions, handshake and response state
  probes.py      TCP flag byte -> which kind of Nmap probe it is
  detectors.py   one rule per technique plus confidence/severity scoring
  report.py      text and JSON output
  cli.py         the analyze and synth commands
  synth.py       generates the labelled sample captures
tools/
  npcap_capture.py  live packet capture through Npcap (ctypes, no extra deps)
  nmap_lab.py       runs real Nmap, captures it, scores the detector
samples/           15 labelled synthetic captures + labels.json
captures/real/     real Nmap captures, nmap logs, validation.json
tests/
```

## Legal

Only use this against hosts you own or have written permission to test. Scanning
someone else's network is illegal in most places, even if you mean no harm. The
lab script refuses any target that is not loopback or a private (RFC1918)
address, so you cannot accidentally point it at a stranger's machine.

# packet-sniffer-co
A Python packet sniffer built with Scapy that captures and analyzes network traffic ethically, with built-in redaction of sensitive fields.


Copilot was used for:
- Boilerplate code structure
- CLI formatting and print formatting
- Unit test scaffolding

Copilot was NOT asked to:
- Capture other people's traffic
- Bypass OS permissions
- Add stealth or persistence features


## Setup

### Requirements
- Python 3.10+
- Scapy: `pip install scapy`
- Npcap (Windows): download from https://npcap.com
- Run terminal as Administrator

### Installation
```bash
pip install scapy
```

---

## How to Run

```bash
python sniffer.py
```

### Parameters (edit inside sniffer.py)
| Parameter | Default | Description |
|-----------|---------|-------------|
| INTERFACE | NPF_{...} | Your Windows network interface |
| PACKET_COUNT | 25 | Max packets to capture |
| BPF_FILTER | tcp or udp port 53 | Filter for TCP and DNS traffic |
| timeout | 60 | Seconds before auto-stop |

### Find your interface
```bash
python -c "from scapy.all import conf; print(conf.iface)"
```

---

## Ethics & Scope

- Only capture traffic on your own machine or authorized network
- All IP addresses are partially masked (e.g. 192.168.1.xxx)
- Sensitive fields are automatically redacted:
  - `Authorization:` headers
  - `Cookie:` headers
  - Email addresses → `[REDACTED_EMAIL]`
  - Password/token query strings → `[REDACTED]`

---

## Features

- TCP and UDP packet capture
- DNS query decoding
- HTTP request line decoding (port 80)
- IP address masking
- Payload redaction
- Protocol summary after capture

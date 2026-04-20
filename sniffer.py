from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
from collections import Counter
import datetime
import re

# ── Counters & log ───────────────────────────────────────────
protocol_counter = Counter()
packet_log = []

# ── Redaction helpers ────────────────────────────────────────
def redact_ip(ip):
    """Partially mask IP address: 192.168.1.105 → 192.168.1.xxx"""
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".xxx"

def redact_payload(payload):
    """Remove sensitive fields from HTTP payload."""
    payload = re.sub(r"Authorization:.*", "Authorization: [REDACTED]", payload)
    payload = re.sub(r"Cookie:.*", "Cookie: [REDACTED]", payload)
    payload = re.sub(r"[\w\.-]+@[\w\.-]+", "[REDACTED_EMAIL]", payload)
    payload = re.sub(r"(password|token|passwd)=[^&\s]*", r"\1=[REDACTED]", payload, flags=re.IGNORECASE)
    return payload

# ── Packet processor ─────────────────────────────────────────
def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip = redact_ip(packet[IP].src)
    dst_ip = redact_ip(packet[IP].dst)
    length = len(packet)
    proto  = "OTHER"
    extra  = ""

    if packet.haslayer(TCP):
        proto = "TCP"
        # Decode HTTP if port 80
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode("utf-8", errors="ignore")
                    payload = redact_payload(payload)
                    first_line = payload.splitlines()[0]
                    extra = f" | HTTP: {first_line}"
                except:
                    pass

    elif packet.haslayer(UDP):
        proto = "UDP"
        # Decode DNS queries
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                domain = packet[DNSQR].qname.decode()
                extra = f" | DNS Query: {domain}"
            except:
                pass

    protocol_counter[proto] += 1
    packet_log.append({"src": src_ip, "dst": dst_ip, "proto": proto, "len": length})
    print(f"[{proto:<5}]  {src_ip:<22} -> {dst_ip:<22}  {length} bytes{extra}")

# ── Summary ──────────────────────────────────────────────────
def print_summary():
    print("\n" + "="*60)
    print("  CAPTURE SUMMARY")
    print("="*60)
    print(f"  Total packets captured : {len(packet_log)}")
    print(f"  Capture ended          : {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    print("\n  Protocol Breakdown:")
    for proto, count in protocol_counter.most_common():
        print(f"    {proto:<8} : {count} packet(s)")
    print("="*60)

# ── Main ─────────────────────────────────────────────────────
if __name__ == "__main__":
    INTERFACE    = r"\Device\NPF_{D85EEB4C-EA8C-4C7F-AF26-F1A64B71EF45}"
    PACKET_COUNT = 25
    BPF_FILTER   = "tcp or udp port 53"

    print("="*60)
    print("  Copilot-Assisted Packet Sniffer")
    print(f"  Filter  : {BPF_FILTER}")
    print(f"  Started : {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    print("="*60)

    try:
        sniff(iface=INTERFACE, filter=BPF_FILTER,
              prn=process_packet, count=PACKET_COUNT, timeout=60)
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        print_summary()
        

from datetime import datetime, timezone


# create one simple packet dictionary used everywhere
def make_packet_info():
    return {
        "time": datetime.now(timezone.utc),
        "src_ip": "",
        "dst_ip": "",
        "src_mac": "",
        "dst_mac": "",
        "protocol": "UNKNOWN",
        "src_port": None,
        "dst_port": None,
        "tcp_flags": "",
        "length": 0,
        "summary": "",
        "extra": {},
    }


# convert packet data into something json can save
def packet_to_json_ready(packet_info):
    clean_packet = {}

    for key in packet_info:
        value = packet_info[key]

        if isinstance(value, datetime):
            clean_packet[key] = value.isoformat()
        elif isinstance(value, dict):
            clean_packet[key] = dict(value)
        else:
            clean_packet[key] = value

    return clean_packet


# read either a plain dictionary or a Scapy packet
def parse_packet(packet):
    packet_info = make_packet_info()

    if isinstance(packet, dict):
        packet_info.update(packet)
        if isinstance(packet_info["time"], str):
            packet_info["time"] = datetime.fromisoformat(packet_info["time"])
        return packet_info

    if hasattr(packet, "time"):
        packet_info["time"] = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)

    if hasattr(packet, "summary"):
        packet_info["summary"] = packet.summary()
    else:
        packet_info["summary"] = str(packet)

    if hasattr(packet, "__len__"):
        packet_info["length"] = len(packet)

    if packet.haslayer("Ether"):
        ethernet = packet.getlayer("Ether")
        packet_info["src_mac"] = str(getattr(ethernet, "src", ""))
        packet_info["dst_mac"] = str(getattr(ethernet, "dst", ""))

    if packet.haslayer("ARP"):
        arp = packet.getlayer("ARP")
        packet_info["protocol"] = "ARP"
        packet_info["src_ip"] = str(getattr(arp, "psrc", ""))
        packet_info["dst_ip"] = str(getattr(arp, "pdst", ""))
        packet_info["src_mac"] = str(getattr(arp, "hwsrc", packet_info["src_mac"]))
        packet_info["dst_mac"] = str(getattr(arp, "hwdst", packet_info["dst_mac"]))
        packet_info["extra"]["arp_op"] = getattr(arp, "op", None)
        return packet_info

    if packet.haslayer("IP"):
        ip_layer = packet.getlayer("IP")
        packet_info["src_ip"] = str(getattr(ip_layer, "src", ""))
        packet_info["dst_ip"] = str(getattr(ip_layer, "dst", ""))
        packet_info["protocol"] = "IP"

    if packet.haslayer("TCP"):
        tcp = packet.getlayer("TCP")
        packet_info["protocol"] = "TCP"
        packet_info["src_port"] = int(getattr(tcp, "sport", 0))
        packet_info["dst_port"] = int(getattr(tcp, "dport", 0))
        packet_info["tcp_flags"] = str(getattr(tcp, "flags", ""))
    elif packet.haslayer("UDP"):
        udp = packet.getlayer("UDP")
        packet_info["protocol"] = "UDP"
        packet_info["src_port"] = int(getattr(udp, "sport", 0))
        packet_info["dst_port"] = int(getattr(udp, "dport", 0))

    return packet_info

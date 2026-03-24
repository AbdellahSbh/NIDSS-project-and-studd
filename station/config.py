import os


# read an integer setting safely
def get_int(name, default_value):
    value = os.getenv(name)
    if value is None:
        return default_value

    try:
        return int(value)
    except ValueError:
        return default_value


# read a boolean-like setting safely
def get_bool(name, default_value):
    value = os.getenv(name)
    if value is None:
        return default_value

    value = value.lower().strip()
    return value in ["1", "true", "yes", "on"]


# load all settings in one simple dictionary
def load_settings():
    settings = {
        "host": os.getenv("ALERT_SERVER_HOST", "0.0.0.0"),
        "port": get_int("ALERT_SERVER_PORT", 9001),
        "shared_secret": os.getenv("STATION_SHARED_SECRET", ""),
        "server_host": os.getenv("ALERT_SERVER_CONNECT_HOST", "127.0.0.1"),
        "server_port": get_int("ALERT_SERVER_CONNECT_PORT", 9001),
        "sniff_iface": os.getenv("STATION_SNIFF_IFACE", ""),
        "pcap_file": os.getenv("STATION_PCAP_FILE", ""),
        "alert_file": os.getenv("STATION_ALERT_LOG", "station_alerts.jsonl"),
        "packet_limit": get_int("STATION_PACKET_LIMIT", 0),
        "udp_port_scan_limit": get_int("STATION_UDP_PORT_SCAN_THRESHOLD", 10),
        "arp_scan_limit": get_int("STATION_ARP_SCAN_THRESHOLD", 10),
        "udp_dos_limit": get_int("STATION_UDP_DOS_THRESHOLD", 10),
        "window_seconds": get_int("STATION_WINDOW_SECONDS", 10),
        "alert_cooldown_seconds": get_int("STATION_ALERT_COOLDOWN_SECONDS", 10),
        "show_alerts": get_bool("STATION_VERBOSE", True),
    }

    if not settings["shared_secret"]:
        print("STATION_SHARED_SECRET is required")
        raise SystemExit(1)

    return settings

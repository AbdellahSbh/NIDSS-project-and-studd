from importlib.util import find_spec

from .alert_manager import print_alerts, save_alerts
from .client import AlertClient
from .config import load_settings
from .detector import check_packet
from .packet_parser import parse_packet
from .state_tracker import create_tracker


# handle one packet from sniffing or a pcap file
def process_packet(packet, tracker, settings, alert_client):
    packet_info = parse_packet(packet)
    alerts = check_packet(packet_info, tracker, settings)

    if not alerts:
        return

    if settings["show_alerts"]:
        print_alerts(alerts)

    save_alerts(alerts, settings["alert_file"])

    for alert in alerts:
        alert_client.send_alert(alert)


# process packets from a pcap file one by one
def run_pcap_mode(settings, tracker, alert_client):
    from scapy.all import rdpcap

    packets = rdpcap(settings["pcap_file"])
    if settings["packet_limit"] > 0:
        packets = packets[: settings["packet_limit"]]

    for packet in packets:
        process_packet(packet, tracker, settings, alert_client)


# sniff live packets and process them as they arrive
def run_live_mode(settings, tracker, alert_client):
    from scapy.all import sniff

    sniff(
        iface=settings["sniff_iface"] or None,
        prn=lambda packet: process_packet(packet, tracker, settings, alert_client),
        store=False,
        count=settings["packet_limit"] if settings["packet_limit"] > 0 else 0,
    )


# start the nids side of the project
def main():
    settings = load_settings()

    if find_spec("scapy") is None:
        print("scapy is not installed, packet monitoring is disabled")
        return

    tracker = create_tracker(settings["window_seconds"])
    alert_client = AlertClient(
        settings["server_host"],
        settings["server_port"],
        settings["shared_secret"],
    )

    if settings["pcap_file"]:
        run_pcap_mode(settings, tracker, alert_client)
    else:
        run_live_mode(settings, tracker, alert_client)


if __name__ == "__main__":
    main()

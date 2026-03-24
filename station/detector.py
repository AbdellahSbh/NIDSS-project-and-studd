from datetime import timedelta

from .state_tracker import (
    update_tracker,
    count_udp_scan_ports,
    count_arp_scan_targets,
    count_udp_dos_packets,
)


# build one alert in the same simple format
def make_alert(level, alert_type, message, packet_info):
    return {
        "level": level,
        "type": alert_type,
        "message": message,
        "packet": packet_info,
    }


# check if FIN, PSH and URG are all set
def is_christmas_tree_packet(packet_info):
    flags = packet_info["tcp_flags"].upper()
    return "F" in flags and "P" in flags and "U" in flags


# stop the same alert from firing too often
def should_send_alert(tracker, alert_type, alert_key, current_time, cooldown_seconds):
    cooldown_limit = current_time - timedelta(seconds=cooldown_seconds)
    last_alert_time = tracker["recent_alerts"].get((alert_type, alert_key))

    if last_alert_time and last_alert_time >= cooldown_limit:
        return False

    tracker["recent_alerts"][(alert_type, alert_key)] = current_time
    return True


# check one packet against the four required rules
def check_packet(packet_info, tracker, settings):
    alerts = []
    update_tracker(tracker, packet_info)

    if packet_info["protocol"] == "UDP" and packet_info["src_ip"] and packet_info["dst_ip"]:
        port_count = count_udp_scan_ports(
            tracker,
            packet_info["src_ip"],
            packet_info["dst_ip"],
            packet_info["time"],
        )
        if port_count >= settings["udp_port_scan_limit"]:
            alert_key = packet_info["src_ip"] + "|" + packet_info["dst_ip"]
            if should_send_alert(
                tracker,
                "udp_port_scan",
                alert_key,
                packet_info["time"],
                settings["alert_cooldown_seconds"],
            ):
                message = (
                    "possible udp port scan from "
                    + packet_info["src_ip"]
                    + " to "
                    + packet_info["dst_ip"]
                    + " ("
                    + str(port_count)
                    + " destination ports in "
                    + str(settings["window_seconds"])
                    + " seconds)"
                )
                alerts.append(make_alert("medium", "udp_port_scan", message, packet_info))

    if packet_info["protocol"] == "ARP" and packet_info["src_ip"]:
        target_count = count_arp_scan_targets(tracker, packet_info["src_ip"], packet_info["time"])
        if target_count >= settings["arp_scan_limit"]:
            alert_key = packet_info["src_ip"]
            if should_send_alert(
                tracker,
                "arp_scan",
                alert_key,
                packet_info["time"],
                settings["alert_cooldown_seconds"],
            ):
                message = (
                    "possible arp scan from "
                    + packet_info["src_ip"]
                    + " ("
                    + str(target_count)
                    + " destination ips in "
                    + str(settings["window_seconds"])
                    + " seconds)"
                )
                alerts.append(make_alert("medium", "arp_scan", message, packet_info))

    if packet_info["protocol"] == "TCP" and packet_info["src_ip"]:
        if is_christmas_tree_packet(packet_info):
            message = (
                "tcp christmas tree packet from "
                + packet_info["src_ip"]
                + " with flags "
                + packet_info["tcp_flags"]
            )
            alerts.append(make_alert("high", "tcp_christmas_tree", message, packet_info))

    if packet_info["protocol"] == "UDP" and packet_info["src_ip"] and packet_info["dst_ip"] and packet_info["dst_port"] is not None:
        udp_count = count_udp_dos_packets(
            tracker,
            packet_info["src_ip"],
            packet_info["dst_ip"],
            packet_info["dst_port"],
            packet_info["time"],
        )
        if udp_count >= settings["udp_dos_limit"]:
            alert_key = (
                packet_info["src_ip"]
                + "|"
                + packet_info["dst_ip"]
                + "|"
                + str(packet_info["dst_port"])
            )
            if should_send_alert(
                tracker,
                "udp_dos",
                alert_key,
                packet_info["time"],
                settings["alert_cooldown_seconds"],
            ):
                message = (
                    "possible udp dos from "
                    + packet_info["src_ip"]
                    + " to "
                    + packet_info["dst_ip"]
                    + ":"
                    + str(packet_info["dst_port"])
                    + " ("
                    + str(udp_count)
                    + " packets in "
                    + str(settings["window_seconds"])
                    + " seconds)"
                )
                alerts.append(make_alert("high", "udp_dos", message, packet_info))

    return alerts

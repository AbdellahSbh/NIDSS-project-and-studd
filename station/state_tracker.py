from collections import deque
from datetime import timedelta


# create the tracker data used by the detection rules
def create_tracker(window_seconds):
    tracker = {
        "window_seconds": window_seconds,
        "udp_scan_ports": {},
        "arp_scan_targets": {},
        "udp_dos_targets": {},
        "recent_alerts": {},
    }
    return tracker


# remove times that are outside the current window
def clean_old_times(times, current_time, window_seconds):
    limit = current_time - timedelta(seconds=window_seconds)
    while times and times[0] < limit:
        times.popleft()


# update the tracker with one new packet
def update_tracker(tracker, packet_info):
    current_time = packet_info["time"]
    window_seconds = tracker["window_seconds"]

    if packet_info["protocol"] == "UDP" and packet_info["src_ip"] and packet_info["dst_ip"] and packet_info["dst_port"] is not None:
        source = packet_info["src_ip"]
        target_ip = packet_info["dst_ip"]
        target_port = packet_info["dst_port"]

        if source not in tracker["udp_scan_ports"]:
            tracker["udp_scan_ports"][source] = {}
        if target_ip not in tracker["udp_scan_ports"][source]:
            tracker["udp_scan_ports"][source][target_ip] = {}
        if target_port not in tracker["udp_scan_ports"][source][target_ip]:
            tracker["udp_scan_ports"][source][target_ip][target_port] = deque()

        tracker["udp_scan_ports"][source][target_ip][target_port].append(current_time)
        clean_old_times(tracker["udp_scan_ports"][source][target_ip][target_port], current_time, window_seconds)

        if source not in tracker["udp_dos_targets"]:
            tracker["udp_dos_targets"][source] = {}
        if target_ip not in tracker["udp_dos_targets"][source]:
            tracker["udp_dos_targets"][source][target_ip] = {}
        if target_port not in tracker["udp_dos_targets"][source][target_ip]:
            tracker["udp_dos_targets"][source][target_ip][target_port] = deque()

        tracker["udp_dos_targets"][source][target_ip][target_port].append(current_time)
        clean_old_times(tracker["udp_dos_targets"][source][target_ip][target_port], current_time, window_seconds)

    if packet_info["protocol"] == "ARP" and packet_info["src_ip"] and packet_info["dst_ip"]:
        source = packet_info["src_ip"]
        target_ip = packet_info["dst_ip"]

        if source not in tracker["arp_scan_targets"]:
            tracker["arp_scan_targets"][source] = {}
        if target_ip not in tracker["arp_scan_targets"][source]:
            tracker["arp_scan_targets"][source][target_ip] = deque()

        tracker["arp_scan_targets"][source][target_ip].append(current_time)
        clean_old_times(tracker["arp_scan_targets"][source][target_ip], current_time, window_seconds)


# count how many different udp ports a source hit on one target recently
def count_udp_scan_ports(tracker, source, target_ip, current_time):
    if source not in tracker["udp_scan_ports"]:
        return 0
    if target_ip not in tracker["udp_scan_ports"][source]:
        return 0

    total = 0
    for port in tracker["udp_scan_ports"][source][target_ip]:
        times = tracker["udp_scan_ports"][source][target_ip][port]
        clean_old_times(times, current_time, tracker["window_seconds"])
        if times:
            total += 1
    return total


# count how many arp targets a source probed recently
def count_arp_scan_targets(tracker, source, current_time):
    if source not in tracker["arp_scan_targets"]:
        return 0

    total = 0
    for target_ip in tracker["arp_scan_targets"][source]:
        times = tracker["arp_scan_targets"][source][target_ip]
        clean_old_times(times, current_time, tracker["window_seconds"])
        if times:
            total += 1
    return total


# count recent udp packets from one source to one target ip and port
def count_udp_dos_packets(tracker, source, target_ip, target_port, current_time):
    if source not in tracker["udp_dos_targets"]:
        return 0
    if target_ip not in tracker["udp_dos_targets"][source]:
        return 0
    if target_port not in tracker["udp_dos_targets"][source][target_ip]:
        return 0

    times = tracker["udp_dos_targets"][source][target_ip][target_port]
    clean_old_times(times, current_time, tracker["window_seconds"])
    return len(times)

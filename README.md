# SCC439 Programming Assessment Starter

This repository now contains a simple Python NIDS with two main parts:

- A packet monitoring client that uses Scapy to inspect traffic, detect the required attack behaviours, print alerts locally, save them to a file, and send them securely.
- A separate alert receiver server that authenticates the client, decrypts incoming alerts, and displays them.

## Required detections implemented

- UDP port scan
- ARP scan
- TCP Christmas tree packets
- UDP DoS

## Files

- `station/config.py`: runtime configuration from environment variables.
- `station/packet_parser.py`: converts Scapy packets into simple packet dictionaries.
- `station/state_tracker.py`: stores the short-term state needed for the four detections.
- `station/detector.py`: detection logic for the four required attack behaviours.
- `station/alert_manager.py`: prints alerts locally and saves them to a JSONL file.
- `station/secure_channel.py`: challenge-response authentication and AES-GCM encryption.
- `station/client.py`: real alert-sending client used by the NIDS.
- `station/server.py`: separate secure alert receiver server.
- `station/main.py`: runs the NIDS packet monitoring side.
- `tester/client.py`: simple manual test script for the secure alert flow.

## Run

Use the helper shell to connect to the coursework containers.

If you are in the main coursework shell, use:

```bash
connect station
```

to open a shell inside the 'station' container, or:

```bash
connect tester
```

to open a shell inside the 'tester' container.

The helper shell is the one that shows commands such as `connect station`, `connect tester`, and `setup` when you type:

```bash
help
```

Start the separate alert receiver server in the 'station' container:

```bash
connect station
cd /workspace
STATION_SHARED_SECRET=abdellah (or whatever as long as it much each other) python3 -m station.server
```

Start the NIDS side in another 'station' container shell:

```bash
connect station
cd /workspace
STATION_SHARED_SECRET=abdellah STATION_SNIFF_IFACE=eth0 python3 -m station
```

Run the provided attack scripts in the 'tester' container:

```bash
connect tester
cd /workspace/tester
python3 udp-port-scan.py 172.20.0.2 10 20
python3 arp-scan.py 172.20.0.0/24
python3 tcp-christmas.py 172.20.0.2 80 1
python3 udp-dos.py 172.20.0.2 80 10
```

Run the simple secure alert test script if needed:

```bash
connect tester
cd /workspace/tester
STATION_SHARED_SECRET=abdellah python3 client.py
```

You can also test the detection logic using the provided PCAP files from the `station` container:

```bash
connect station
cd /workspace
STATION_SHARED_SECRET=abdellah STATION_PCAP_FILE=packet_captures/udp-port-scan.pcap python3 -m station
STATION_SHARED_SECRET=abdellah STATION_PCAP_FILE=packet_captures/arp-scan.pcap python3 -m station
STATION_SHARED_SECRET=abdellah STATION_PCAP_FILE=packet_captures/tcp-christmas.pcap python3 -m station
STATION_SHARED_SECRET=abdellah STATION_PCAP_FILE=packet_captures/udp-dos.pcap python3 -m station
```

Use the same value for `STATION_SHARED_SECRET` on both the server and the NIDS client. The example value `abdellah` is only a sample and can be replaced with any shared secret.

## Useful environment variables

- 'ALERT_SERVER_HOST'
- 'ALERT_SERVER_PORT'
- 'ALERT_SERVER_CONNECT_HOST'
- 'ALERT_SERVER_CONNECT_PORT'
- 'STATION_SHARED_SECRET'
- 'STATION_PCAP_FILE'
- 'STATION_SNIFF_IFACE'
- 'STATION_ALERT_LOG'
- 'STATION_PACKET_LIMIT'
- 'STATION_UDP_PORT_SCAN_THRESHOLD'
- 'STATION_ARP_SCAN_THRESHOLD'
- 'STATION_UDP_DOS_THRESHOLD'
- 'STATION_WINDOW_SECONDS'

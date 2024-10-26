# SniffDog - Packet Sniffing Tool

Sniffdog is a lightweight, no-dependencies, Python-based packet sniffing CLI tool designed to capture and analyze Ethernet traffic.

<hr>
<div align="centre">
<img src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black">
<img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white">
</div>

## Table of contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Examples](#examples)
5. [Output](#output)
6. [Limitations](#limitations)
7. [License](#license)

## Features

- <b>Detailed Packet Analysis</b>: Capture and display Ethernet frame details, IPv4 headers, protocol information, and transmitted payloads.
- <b>CLI Options</b>:
  - `--keep-alive`: Displays the keep-alive packets
  - `--write-log`: Logs captured packets to a file for further analysis
- <b>No External Libraries</b>: Built using only native Python Libraries

## Installation

Clone this repostiory

```bash
git clone https://github.com/p4th4k/SniffDog.git
cd SniffDog
```

## Usage

Run SniffDog with optional commands:

```bash
python3 main.py [--keep-alive] [--write-log]
```

## Examples

<b>1. Capture and disaply packets</b>:

```bash
sudo python3 sniffEther.py
```

<b>2. Capture and display packets along with keep-alive packets</b>

```bash
sudo python3 sniffEther.py --keep-alive
```

<b>3. Caputre and display packets along with logging</b>

```bash
sudo python3 sniffEther.py --write-log
```

<b>4. Capture and display packets along with keep-alive and logging</b>

```bash
sudo python3 sniffEther.py --keep-alive --write-log
```

## Output

For each captured packet, the tool provides:

- <b>Ethernet Frame</b>: MAC addresses, Protocol.
- <b>IPv4 Header</b>: Version, Header Length, Source/destination IP, TTL, protocol.
- <b>Protocol Information</b>: Packet details for ICMP, TCP, UDP and others.
- <b>Payload</b>: Raw Data transmitted within the packet encoded in ASCII format.

## Limitations

- Designed for Ethernet-based networks
- Requires root privileges for packet capture
- Works best in environment where raw socket access is permitted

## License

[MIT](https://choosealicense.com/licenses/mit/)

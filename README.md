
# 👨🏻‍💻 Scapy RIP Lab

This project is a small networking lab built around Scapy and RIP (Routing Information Protocol). It provides a
containerized environment with a fake router that sends RIP updates, a packet sniffer that observes RIP traffic, and an
FRR-based RIP router to act as a real routing neighbor. The goal is to explore routing behavior and understand how
malicious RIP updates can influence route selection.

> [!NOTE]  
> This repository is intended for educational use in networking classes or labs.

## 📦 What’s inside

- 🛰️ **Fake router**: Sends RIP v2 updates based on a YAML configuration.
- 🕵️ **Sniffer**: Captures RIP traffic (UDP/520) and logs packet details.
- 🧭 **RIP router (FRR)**: Real routing daemon for testing route exchange.
- 🐳 **Docker topology**: A single bridge network `10.0.0.0/24` that connects all services.

## 🎬 Demo video

Below I present how **fake-router** changes route to `142.250.120.0/24` network, so packets are sent via **fake-router** when pinging **google.com**.

<video src="https://github.com/user-attachments/assets/504714b4-ba9c-48b3-a3c9-2b8ee1dcd8d6" controls width="100%"></video>

## 🗂️ Project layout

- `src/fake_router.py` – entry point for sending RIP updates
- `src/maliciouse_rip/maliciouse_rip_sender.py` – constructs and transmits RIP packets
- `src/sniffer.py` – simple RIP sniffer
- `src/conf/` – YAML configs for RIP updates
- `docker/` – container definitions and compose topology

## ✅ Requirements

- Docker and Docker Compose
- (Optional) Python 3.12+ if running locally without containers

## 🐋 Running with Docker

To build and run all containers use the following command:

```bash
docker compose -f docker/docker-compose.yaml up --build
```

The `host` container is configured to route traffic through the `rip-router` container (`10.0.0.254`).

> [!TIP]
> Use `docker exec -it host /bin/bash` to attach virtual terminal which can be used to test `ping` or `traceroute` commands.

## ⚙️ Configuration

RIP update parameters are stored in YAML files under `src/conf/`. Example fields include:

- `addr` – route address
- `mask` – subnet mask
- `metric` – route metric
- `nextHop` – optional next hop address

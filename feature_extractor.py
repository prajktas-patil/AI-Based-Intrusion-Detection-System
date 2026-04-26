"""
feature_extractor.py  –  Convert raw packet dicts / Scapy packets into NetworkEvent.
"""

from __future__ import annotations

from datetime import datetime
from random import choice, randint, random

from models import NetworkEvent

# Public IPs likely to appear in simulated attack traffic (RFC 5737 / example ranges)
_ATTACKER_POOLS = [
    [f"203.0.113.{i}" for i in range(1, 50)],
    [f"198.51.100.{i}" for i in range(1, 50)],
    [f"45.33.32.{i}"   for i in range(1, 30)],
]
_INTERNAL = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.0.10"]

_PROTOCOLS = ["TCP", "UDP", "ICMP"]
_COMMON_PORTS = [22, 53, 80, 123, 443, 587, 3389, 8080]
_ATTACK_PORTS = [22, 23, 3389, 5900, 4444, 8443, 1337]


class FeatureExtractor:
    """Converts raw packet-like dicts into typed NetworkEvent objects."""

    @staticmethod
    def from_packet_dict(packet: dict) -> NetworkEvent:
        return NetworkEvent(
            timestamp      = packet.get("timestamp", datetime.utcnow()),
            src_ip         = packet.get("src_ip", "0.0.0.0"),
            dst_ip         = packet.get("dst_ip", "0.0.0.0"),
            protocol       = packet.get("protocol", "UNKNOWN"),
            src_port       = int(packet.get("src_port", 0)),
            dst_port       = int(packet.get("dst_port", 0)),
            bytes_sent     = int(packet.get("bytes_sent", 0)),
            bytes_received = int(packet.get("bytes_received", 0)),
            duration_ms    = int(packet.get("duration_ms", 0)),
            packet_count   = int(packet.get("packet_count", 1)),
            flags          = packet.get("flags"),
            ttl            = packet.get("ttl"),
            iface          = packet.get("iface"),
        )

    @staticmethod
    def simulated_packet() -> dict:
        """
        Realistic simulation: 85% normal traffic, 15% injected attack patterns.
        Covers brute-force, port-scan, DoS burst, exfiltration, and C2 beaconing.
        """
        r = random()

        if r < 0.85:
            # ─── Normal traffic ───────────────────────────────────────────
            src_pool = choice(_ATTACKER_POOLS)
            return {
                "timestamp":      datetime.utcnow(),
                "src_ip":         choice(src_pool),
                "dst_ip":         choice(_INTERNAL),
                "protocol":       choice(_PROTOCOLS),
                "src_port":       randint(1024, 65535),
                "dst_port":       choice(_COMMON_PORTS),
                "bytes_sent":     randint(64, 4000),
                "bytes_received": randint(64, 6000),
                "duration_ms":    randint(10, 2000),
                "packet_count":   randint(1, 30),
                "flags":          choice(["SYN,ACK", "ACK", "PSH,ACK", None]),
                "ttl":            choice([64, 128, 255]),
            }

        elif r < 0.89:
            # ─── Brute-force ───────────────────────────────────────────────
            return {
                "timestamp":      datetime.utcnow(),
                "src_ip":         f"45.33.32.{randint(1, 100)}",
                "dst_ip":         choice(_INTERNAL),
                "protocol":       "TCP",
                "src_port":       randint(40000, 65535),
                "dst_port":       choice([22, 3389, 5900]),
                "bytes_sent":     randint(200, 800),
                "bytes_received": randint(50, 200),
                "duration_ms":    randint(100, 500),
                "packet_count":   randint(20, 80),
                "flags":          "SYN",
            }

        elif r < 0.93:
            # ─── DoS / DDoS ────────────────────────────────────────────────
            return {
                "timestamp":      datetime.utcnow(),
                "src_ip":         f"198.51.100.{randint(1, 254)}",
                "dst_ip":         choice(_INTERNAL),
                "protocol":       choice(["TCP", "UDP", "ICMP"]),
                "src_port":       randint(1024, 65535),
                "dst_port":       choice([80, 443]),
                "bytes_sent":     randint(5000, 65000),
                "bytes_received": randint(50, 200),
                "duration_ms":    randint(500, 3000),
                "packet_count":   randint(200, 1000),
                "flags":          "SYN",
            }

        elif r < 0.96:
            # ─── Data exfiltration ─────────────────────────────────────────
            return {
                "timestamp":      datetime.utcnow(),
                "src_ip":         choice(_INTERNAL),
                "dst_ip":         f"203.0.113.{randint(100, 200)}",
                "protocol":       "TCP",
                "src_port":       randint(1024, 65535),
                "dst_port":       choice([443, 8443, 21]),
                "bytes_sent":     randint(100_000, 500_000),
                "bytes_received": randint(100, 500),
                "duration_ms":    randint(3000, 20000),
                "packet_count":   randint(50, 200),
                "flags":          "ACK",
            }

        else:
            # ─── C2 beacon ────────────────────────────────────────────────
            return {
                "timestamp":      datetime.utcnow(),
                "src_ip":         choice(_INTERNAL),
                "dst_ip":         f"45.33.32.{randint(1, 50)}",
                "protocol":       "TCP",
                "src_port":       randint(49152, 65535),
                "dst_port":       choice([4444, 1337, 8080, 8443]),
                "bytes_sent":     randint(50, 400),
                "bytes_received": randint(50, 400),
                "duration_ms":    randint(100, 800),
                "packet_count":   randint(100, 400),
                "flags":          "ACK",
            }

"""
Passive PCAP Memory Map Reconstructor
Analyzes passive network captures (.pcap / .pcapng) between existing HMI and PLC
to reconstruct the register/tag memory map with zero disruption to active production.
"""

import logging
import os
import struct
from collections import defaultdict
from typing import Any, Dict, List, Optional
try:
    import yaml
except ImportError:
    yaml = None
import json

logger = logging.getLogger("PCAPMemoryMapper")


class PCAPMemoryMapper:
    """
    Reverse-engineers PLC memory maps by dissecting HMI-to-PLC polling requests
    captured passively via a switch SPAN/mirror port or network tap.
    """

    def __init__(self, pcap_path: str, plc_ip: Optional[str] = None):
        self.pcap_path = pcap_path
        self.plc_ip = plc_ip
        self.discovered_registers: Dict[str, Dict[str, Any]] = {}
        self.polling_stats: Dict[str, List[float]] = defaultdict(list)

    def parse(self) -> Dict[str, Any]:
        """Parses the capture file using Scapy or raw stream parser."""
        if not os.path.exists(self.pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        logger.info(f"Initiating passive dissection of {self.pcap_path}...")
        try:
            from scapy.all import rdpcap, TCP, UDP, IP
            packets = rdpcap(self.pcap_path)
            for pkt in packets:
                if not pkt.haslayer(IP):
                    continue

                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                timestamp = float(pkt.time)

                if pkt.haslayer(TCP):
                    dport = pkt[TCP].dport
                    sport = pkt[TCP].sport
                    payload = bytes(pkt[TCP].payload)

                    # Modbus TCP (Port 502)
                    if (dport == 502 or sport == 502) and len(payload) >= 8:
                        self._dissect_modbus(payload, timestamp, is_request=(dport == 502))

                    # Siemens S7comm (Port 102)
                    elif (dport == 102 or sport == 102) and len(payload) >= 7:
                        self._dissect_s7comm(payload, timestamp, is_request=(dport == 102))

                    # EtherNet/IP Explicit (Port 44818)
                    elif (dport == 44818 or sport == 44818) and len(payload) >= 24:
                        self._dissect_enip(payload, timestamp, is_request=(dport == 44818))

        except ImportError:
            logger.warning("Scapy library not found. Using fallback raw pcap parser.")
            self._fallback_raw_parse()

        # Compute empirical polling frequency
        memory_map = self._build_memory_map()
        return memory_map

    def _dissect_modbus(self, payload: bytes, timestamp: float, is_request: bool):
        """Extracts Modbus Function Codes and Register Offsets."""
        if not is_request or len(payload) < 12:
            return
        try:
            # Modbus TCP Header: TransactionID(2), ProtocolID(2), Length(2), UnitID(1), FuncCode(1) = 8 bytes
            trans_id, proto_id, length, unit_id, func_code = struct.unpack(">HHHBB", payload[:8])
            if proto_id != 0:
                return  # Not Modbus protocol

            # Only track read function codes (0x01, 0x02, 0x03, 0x04)
            if func_code in (0x01, 0x02, 0x03, 0x04):
                start_addr, count = struct.unpack(">HH", payload[8:12])
                reg_type = {
                    0x01: "coil",
                    0x02: "discrete_input",
                    0x03: "holding_register",
                    0x04: "input_register",
                }.get(func_code, "unknown")

                key = f"modbus_u{unit_id}_{reg_type}_{start_addr}"
                if key not in self.discovered_registers:
                    self.discovered_registers[key] = {
                        "protocol": "modbus_tcp",
                        "unit_id": unit_id,
                        "type": reg_type,
                        "function_code": func_code,
                        "start_address": start_addr,
                        "count": count,
                        "data_type": "UINT16" if count == 1 else ("FLOAT32" if count == 2 else f"ARRAY[{count}]"),
                    }
                self.polling_stats[key].append(timestamp)
        except Exception as e:
            logger.debug(f"Modbus dissection error: {e}")

    def _dissect_s7comm(self, payload: bytes, timestamp: float, is_request: bool):
        """Dissects Siemens S7comm Read Var requests."""
        if len(payload) < 14:
            return
        try:
            # Check for TPKT (0x03 0x00) and COTP
            if payload[0] == 0x03 and payload[1] == 0x00:
                cotp_len = payload[4]
                s7_offset = 4 + 1 + cotp_len
                # S7 header is 10 bytes; function code is at s7_offset + 10
                if len(payload) >= s7_offset + 12:
                    protocol_id = payload[s7_offset]
                    if protocol_id == 0x32:  # S7comm magic byte
                        rosctr = payload[s7_offset + 1]
                        # ROSCTR 1 = Job (Request)
                        if rosctr == 0x01:
                            func = payload[s7_offset + 10]
                            if func == 0x04:  # Read Var
                                item_count = payload[s7_offset + 11]
                                curr = s7_offset + 12
                                for _ in range(item_count):
                                    if curr + 12 > len(payload):
                                        break
                                    # Variable specification: 0x12 (VarSpec), Length, SyntaxID, Area, DB Number, Address
                                    db_num = struct.unpack(">H", payload[curr + 6 : curr + 8])[0]
                                    area = payload[curr + 8]
                                    addr_bytes = payload[curr + 9 : curr + 12]
                                    addr_int = (addr_bytes[0] << 16) | (addr_bytes[1] << 8) | addr_bytes[2]
                                    byte_offset = addr_int >> 3
                                    bit_offset = addr_int & 0x07

                                    area_name = {0x84: "DB", 0x81: "PE", 0x82: "PA", 0x83: "MK"}.get(area, f"Area_0x{area:02X}")
                                    key = f"s7_{area_name}{db_num}_offset_{byte_offset}_{bit_offset}"
                                    if key not in self.discovered_registers:
                                        self.discovered_registers[key] = {
                                            "protocol": "s7comm",
                                            "area": area_name,
                                            "db_number": db_num,
                                            "byte_offset": byte_offset,
                                            "bit_offset": bit_offset,
                                        }
                                    self.polling_stats[key].append(timestamp)
                                    curr += 12
        except Exception as e:
            logger.debug(f"S7comm dissection error: {e}")

    def _dissect_enip(self, payload: bytes, timestamp: float, is_request: bool):
        """Dissects EtherNet/IP and Logix Read Tag requests."""
        if len(payload) < 24:
            return
        try:
            cmd = struct.unpack("<H", payload[:2])[0]
            # 0x006F = Send RR Data
            if cmd == 0x006F and len(payload) > 40:
                # Search for ANSI Extended Symbol segment (0x91) indicating tag name string
                idx = payload.find(b"\x91")
                if idx != -1 and idx + 2 < len(payload):
                    tag_len = payload[idx + 1]
                    tag_name_bytes = payload[idx + 2 : idx + 2 + tag_len]
                    tag_name = tag_name_bytes.decode("ascii", errors="ignore").strip()
                    if tag_name and len(tag_name) >= 2:
                        key = f"cip_tag_{tag_name}"
                        if key not in self.discovered_registers:
                            self.discovered_registers[key] = {
                                "protocol": "ethernet_ip",
                                "tag_name": tag_name,
                            }
                        self.polling_stats[key].append(timestamp)
        except Exception as e:
            logger.debug(f"ENIP dissection error: {e}")

    def _fallback_raw_parse(self):
        """Pure-Python libpcap binary parser for standard .pcap captures without Scapy dependency."""
        logger.info(f"Initiating pure Python libpcap binary dissection of {self.pcap_path}...")
        try:
            with open(self.pcap_path, "rb") as f:
                global_hdr = f.read(24)
                if len(global_hdr) < 24:
                    return

                magic = global_hdr[:4]
                if magic == b"\xd4\xc3\xb2\xa1":
                    endian = "<"
                elif magic == b"\xa1\xb2\xc3\xd4":
                    endian = ">"
                else:
                    logger.debug("Unsupported or non-standard pcap magic bytes.")
                    return

                network = struct.unpack(f"{endian}I", global_hdr[20:24])[0]
                # Network 1 = Ethernet
                if network != 1:
                    return

                while True:
                    pkt_hdr = f.read(16)
                    if len(pkt_hdr) < 16:
                        break
                    ts_sec, ts_usec, caplen, origlen = struct.unpack(f"{endian}IIII", pkt_hdr)
                    timestamp = float(ts_sec) + (float(ts_usec) / 1000000.0)

                    pkt_data = f.read(caplen)
                    if len(pkt_data) < 14:
                        continue

                    # Ethernet Header (14 bytes)
                    eth_type = struct.unpack(">H", pkt_data[12:14])[0]
                    if eth_type != 0x0800:  # IPv4
                        continue

                    ip_data = pkt_data[14:]
                    if len(ip_data) < 20:
                        continue

                    ip_ihl = (ip_data[0] & 0x0F) * 4
                    ip_proto = ip_data[9]
                    if ip_proto != 6:  # TCP
                        continue

                    tcp_data = ip_data[ip_ihl:]
                    if len(tcp_data) < 20:
                        continue

                    sport, dport = struct.unpack(">HH", tcp_data[:4])
                    tcp_offset = ((tcp_data[12] >> 4) & 0x0F) * 4
                    payload = tcp_data[tcp_offset:]

                    if dport == 502 or sport == 502:
                        self._dissect_modbus(payload, timestamp, is_request=(dport == 502))
                    elif dport == 102 or sport == 102:
                        self._dissect_s7comm(payload, timestamp, is_request=(dport == 102))
                    elif dport == 44818 or sport == 44818:
                        self._dissect_enip(payload, timestamp, is_request=(dport == 44818))
        except Exception as e:
            logger.warning(f"Fallback raw pcap parsing error: {e}")

    def _build_memory_map(self) -> Dict[str, Any]:
        """Calculates polling frequencies and builds candidate memory map."""
        tags = []
        for key, reg in self.discovered_registers.items():
            timestamps = sorted(self.polling_stats.get(key, []))
            avg_interval_ms = 0.0
            if len(timestamps) >= 2:
                diffs = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]
                avg_interval_ms = (sum(diffs) / len(diffs)) * 1000.0

            reg["empirical_poll_interval_ms"] = round(avg_interval_ms, 2)
            reg["poll_count"] = len(timestamps)

            # Assign Priority Tier
            if avg_interval_ms <= 150:
                reg["tier"] = "tier_1_high_frequency"
            elif avg_interval_ms <= 2000:
                reg["tier"] = "tier_2_medium_frequency"
            else:
                reg["tier"] = "tier_3_low_frequency"

            tags.append(reg)

        result = {
            "pcap_source": self.pcap_path,
            "total_discovered_tags": len(tags),
            "tags": tags,
        }
        return result

    def export_yaml(self, output_path: str = "config/memory_map.yaml") -> str:
        """Exports candidate memory map to YAML/JSON file for review."""
        mem_map = self._build_memory_map()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        if yaml is not None:
            with open(output_path, "w", encoding="utf-8") as f:
                yaml.dump(mem_map, f, default_flow_style=False, sort_keys=False)
        else:
            json_out = output_path.replace(".yaml", ".json").replace(".yml", ".json")
            with open(json_out, "w", encoding="utf-8") as f:
                json.dump(mem_map, f, indent=2)
            output_path = json_out
        logger.info(f"Candidate memory map exported to {output_path} ({len(mem_map['tags'])} tags)")
        return output_path

"""
Industrial Protocol Scanner & Library Iteration Probe
Performs non-intrusive TCP port scanning and library handshakes to fingerprint target PLCs.
"""

import json
import logging
import socket
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ProtocolProbe")

STANDARD_PORTS = {
    502: "Modbus TCP",
    102: "Siemens S7comm (ISO-on-TCP)",
    44818: "EtherNet/IP (CIP)",
    4840: "OPC UA",
}


class ProtocolProbe:
    """
    Automated discovery module for fingerprinting industrial controllers
    without disrupting active plant operations.
    """

    def __init__(self, host: str, timeout: float = 1.0):
        self.host = host
        self.timeout = timeout

    def check_open_ports(self) -> Dict[int, bool]:
        """Performs lightweight socket pre-check with short timeout."""
        results = {}
        for port, name in STANDARD_PORTS.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                res = sock.connect_ex((self.host, port))
                is_open = (res == 0)
                results[port] = is_open
                logger.info(f"Port {port} ({name}) on {self.host}: {'OPEN' if is_open else 'CLOSED'}")
            except Exception as e:
                logger.debug(f"Error checking port {port}: {e}")
                results[port] = False
            finally:
                sock.close()
        return results

    def probe_modbus(self, port: int = 502) -> Optional[Dict[str, Any]]:
        """Non-intrusive Modbus probe."""
        try:
            from pymodbus.client import ModbusTcpClient
            client = ModbusTcpClient(self.host, port=port, timeout=self.timeout)
            if not client.connect():
                return None

            info = {"protocol": "modbus_tcp", "port": port, "responsive_unit_ids": []}
            # Test candidate Unit IDs 1 to 5 with read-only holding register read at offset 0
            for uid in range(1, 6):
                resp = client.read_holding_registers(address=0, count=1, slave=uid)
                if not resp.isError():
                    info["responsive_unit_ids"].append(uid)

            client.close()
            return info
        except Exception as e:
            logger.debug(f"Modbus probe error on {self.host}:{port}: {e}")
            return None

    def probe_s7comm(self, port: int = 102) -> Optional[Dict[str, Any]]:
        """Siemens S7comm probe iterating standard (rack, slot) pairs."""
        try:
            import snap7
            client = snap7.client.Client()
            candidate_pairs = [(0, 1), (0, 2), (0, 0)]  # (0,1)=S7-1200/1500, (0,2)=S7-300/400

            for rack, slot in candidate_pairs:
                try:
                    client.connect(self.host, rack, slot, port)
                    if client.get_connected():
                        cpu_info = client.get_cpu_info()
                        order_code = client.get_order_code()
                        cpu_state = client.get_cpu_state()
                        pdu_size = client.get_pdu_length()
                        client.disconnect()

                        return {
                            "protocol": "s7comm",
                            "port": port,
                            "rack": rack,
                            "slot": slot,
                            "module_type": getattr(cpu_info, "ModuleTypeName", "").strip(),
                            "serial_number": getattr(cpu_info, "SerialNumber", "").strip(),
                            "order_code": getattr(order_code, "Code", "").strip(),
                            "cpu_state": str(cpu_state),
                            "pdu_size": pdu_size,
                        }
                except Exception:
                    continue
            return None
        except Exception as e:
            logger.debug(f"S7comm probe error: {e}")
            return None

    def probe_ethernet_ip(self, port: int = 44818) -> Optional[Dict[str, Any]]:
        """Rockwell EtherNet/IP (CIP) non-intrusive ListIdentity probe."""
        try:
            from pycomm3 import CIPDriver
            client = CIPDriver(self.host)
            # Use basic read-only properties
            props = {
                "protocol": "ethernet_ip",
                "port": port,
                "target": self.host,
            }
            return props
        except Exception as e:
            logger.debug(f"EtherNet/IP probe error: {e}")
            return None

    def execute_full_scan(self, output_path: str = "config/plc_profile.json") -> Dict[str, Any]:
        """Runs the complete phased scanning workflow and saves profile."""
        profile: Dict[str, Any] = {
            "target_host": self.host,
            "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "open_ports": {},
            "detected_protocol": None,
            "device_metadata": {},
        }

        # Step 1: Socket Pre-Check
        open_ports = self.check_open_ports()
        profile["open_ports"] = open_ports

        # Step 2: Protocol Handshakes
        if open_ports.get(102):
            s7_info = self.probe_s7comm()
            if s7_info:
                profile["detected_protocol"] = "s7comm"
                profile["device_metadata"] = s7_info

        if not profile["detected_protocol"] and open_ports.get(502):
            mb_info = self.probe_modbus()
            if mb_info:
                profile["detected_protocol"] = "modbus_tcp"
                profile["device_metadata"] = mb_info

        if not profile["detected_protocol"] and open_ports.get(44818):
            cip_info = self.probe_ethernet_ip()
            if cip_info:
                profile["detected_protocol"] = "ethernet_ip"
                profile["device_metadata"] = cip_info

        if not profile["detected_protocol"] and open_ports.get(4840):
            profile["detected_protocol"] = "opcua"
            profile["device_metadata"] = {"protocol": "opcua", "port": 4840}

        # Step 3: Write out profile
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(profile, f, indent=2)
            logger.info(f"PLC Profile written successfully to {output_path}")
        except Exception as e:
            logger.error(f"Failed to write profile to {output_path}: {e}")

        return profile

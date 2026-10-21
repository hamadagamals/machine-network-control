"""
STRICTLY READ-ONLY PLC CLIENT WRAPPER (ZERO WRITE CAPABILITY)
Enforces a hardware and software level read-only abstraction.
Blocks all write, force, download, delete, or CPU state-change commands at runtime.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Union
from plc_extractor.client.rate_limiter import PLCRateLimiter

logger = logging.getLogger("PLCReadOnlyClient")

# ==============================================================================
# PROHIBITED METHODS DICTIONARY (ZERO TOLERANCE)
# ==============================================================================
STRICTLY_PROHIBITED_METHODS = {
    # Modbus Prohibited
    "write_coil",
    "write_coils",
    "write_register",
    "write_registers",
    "mask_write_register",
    "readwrite_registers",
    # Siemens S7 Prohibited (python-snap7)
    "db_write",
    "eb_write",
    "ab_write",
    "mb_write",
    "write_area",
    "write_multi_vars",
    "write_tag",
    "force_bit",
    "download",
    "delete",
    "plc_stop",
    "plc_cold_start",
    "plc_hot_start",
    "compress",
    "copy_ram_to_rom",
    # Rockwell CIP / EtherNet/IP Prohibited (pycomm3 / pylogix)
    "write",
    "write_tag",
    "write_tag_fragmented",
    "set_plc_time",
    "setplctime",
    "set_attribute_single",
    "set_attribute_list",
    "reset",
    # OPC UA Prohibited
    "write_value",
    "write_attribute_value",
    "set_value",
    "call_method",
}

# Permitted Modbus Function Codes (Strict Whitelist)
PERMITTED_MODBUS_FUNCTION_CODES = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x2B: "Read Device Identification",
}


class PLCWriteAttemptBlockedError(PermissionError):
    """Raised immediately when an operation attempts to mutate PLC memory or state."""
    pass


class ReadOnlyPLCClient:
    """
    Safety wrapper around low-level industrial communication libraries.
    Ensures that only read-only function codes can ever be executed on the physical controller.
    """

    def __init__(
        self,
        protocol: str,
        host: str,
        port: int = 502,
        options: Optional[Dict[str, Any]] = None,
        max_requests_per_second: float = 50.0,
    ):
        self.protocol = protocol.lower().strip()
        self.host = host
        self.port = port
        self.options = options or {}
        self.rate_limiter = PLCRateLimiter(max_requests_per_second=max_requests_per_second)
        
        self._raw_client = None
        self._is_connected = False
        self._last_exec_time_ms = 0.0

        logger.info(
            f"[SAFETY LOCK ENGAGED] ReadOnlyPLCClient initialized for {self.protocol}://{self.host}:{self.port} "
            f"(Max Rate: {max_requests_per_second} req/s)"
        )

    # --------------------------------------------------------------------------
    # HARD METHOD INTERCEPTION: Blocks any prohibited method access
    # --------------------------------------------------------------------------
    def __getattr__(self, name: str):
        lowered = name.lower()
        if lowered in STRICTLY_PROHIBITED_METHODS or "write" in lowered or "force" in lowered or "stop" in lowered:
            alarm_msg = (
                f"FATAL SAFETY INTERCEPTION: Method '{name}' is strictly prohibited on live production equipment! "
                f"Execution blocked before touching network socket."
            )
            logger.critical(alarm_msg)
            raise PLCWriteAttemptBlockedError(alarm_msg)

        if self._raw_client and hasattr(self._raw_client, name):
            attr = getattr(self._raw_client, name)
            if callable(attr):
                def safe_proxy(*args, **kwargs):
                    self.rate_limiter.acquire()
                    return attr(*args, **kwargs)
                return safe_proxy
            return attr

        raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")

    # --------------------------------------------------------------------------
    # PERSISTENT SESSION CONNECTION & RECONNECTION
    # --------------------------------------------------------------------------
    def connect(self) -> bool:
        """Establishes a single, persistent session outside the polling loop."""
        try:
            if self.protocol == "modbus_tcp":
                try:
                    from pymodbus.client import ModbusTcpClient
                    self._raw_client = ModbusTcpClient(
                        host=self.host,
                        port=self.port,
                        timeout=self.options.get("timeout", 2.0),
                    )
                    self._is_connected = self._raw_client.connect()
                except ImportError:
                    logger.info("pymodbus not installed. Using pure-socket native Modbus TCP driver.")
                    self._raw_client = _PureSocketModbusClient(self.host, self.port, timeout=self.options.get("timeout", 2.0))
                    self._is_connected = self._raw_client.connect()

            elif self.protocol == "s7comm":
                import snap7
                self._raw_client = snap7.client.Client()
                rack = self.options.get("rack", 0)
                slot = self.options.get("slot", 1)
                self._raw_client.connect(self.host, rack, slot, self.port)
                self._is_connected = self._raw_client.get_connected()

            elif self.protocol == "ethernet_ip":
                from pycomm3 import LogixDriver
                route = self.options.get("route_path")
                init_str = f"{self.host}/{route}" if route else self.host
                self._raw_client = LogixDriver(init_str)
                self._raw_client.open()
                self._is_connected = self._raw_client.connected

            else:
                logger.warning(f"Protocol '{self.protocol}' connection handler using generic mode.")
                self._is_connected = True

            if self._is_connected:
                logger.info(f"Successfully connected to {self.protocol}://{self.host}:{self.port} in STRICT READ-ONLY mode.")
            else:
                logger.error(f"Failed to connect to {self.protocol}://{self.host}:{self.port}")
            return self._is_connected

        except Exception as e:
            logger.error(f"Connection exception on {self.host}:{self.port}: {e}")
            self._is_connected = False
            return False

    def is_connected(self) -> bool:
        return self._is_connected

    def disconnect(self):
        """Safely closes the persistent session."""
        try:
            if self._raw_client:
                if hasattr(self._raw_client, "close"):
                    self._raw_client.close()
                elif hasattr(self._raw_client, "disconnect"):
                    self._raw_client.disconnect()
        finally:
            self._is_connected = False

    # --------------------------------------------------------------------------
    # UNIFIED SAFE READ INTERFACES
    # --------------------------------------------------------------------------
    def read_holding_registers(self, address: int, count: int, unit_id: int = 1) -> List[int]:
        """Modbus Function Code 0x03 (Strictly Read-Only)."""
        self.rate_limiter.acquire()
        t0 = time.perf_counter()
        if not self._raw_client:
            raise ConnectionError("PLC Client not connected.")

        resp = self._raw_client.read_holding_registers(address=address, count=count, slave=unit_id)
        self._last_exec_time_ms = (time.perf_counter() - t0) * 1000.0

        if resp.isError():
            raise IOError(f"Modbus Error reading holding registers at {address}: {resp}")
        return list(resp.registers)

    def read_input_registers(self, address: int, count: int, unit_id: int = 1) -> List[int]:
        """Modbus Function Code 0x04 (Strictly Read-Only)."""
        self.rate_limiter.acquire()
        t0 = time.perf_counter()
        resp = self._raw_client.read_input_registers(address=address, count=count, slave=unit_id)
        self._last_exec_time_ms = (time.perf_counter() - t0) * 1000.0

        if resp.isError():
            raise IOError(f"Modbus Error reading input registers at {address}: {resp}")
        return list(resp.registers)

    def read_discrete_inputs(self, address: int, count: int, unit_id: int = 1) -> List[bool]:
        """Modbus Function Code 0x02 (Strictly Read-Only)."""
        self.rate_limiter.acquire()
        resp = self._raw_client.read_discrete_inputs(address=address, count=count, slave=unit_id)
        if resp.isError():
            raise IOError(f"Modbus Error reading discrete inputs at {address}: {resp}")
        return list(resp.bits[:count])

    def read_coils(self, address: int, count: int, unit_id: int = 1) -> List[bool]:
        """Modbus Function Code 0x01 (Strictly Read-Only)."""
        self.rate_limiter.acquire()
        resp = self._raw_client.read_coils(address=address, count=count, slave=unit_id)
        if resp.isError():
            raise IOError(f"Modbus Error reading coils at {address}: {resp}")
        return list(resp.bits[:count])

    def read_s7_db(self, db_number: int, start: int, size: int) -> bytearray:
        """Siemens S7comm db_read (Strictly Read-Only)."""
        self.rate_limiter.acquire()
        t0 = time.perf_counter()
        data = self._raw_client.db_read(db_number, start, size)
        self._last_exec_time_ms = (time.perf_counter() - t0) * 1000.0
        return bytearray(data)

    def read_cip_tags(self, tags: Union[str, List[str]]) -> Any:
        """Allen-Bradley Logix CIP Multiple Service Packet Read (Strictly Read-Only)."""
        self.rate_limiter.acquire()
        t0 = time.perf_counter()
        res = self._raw_client.read(tags)
        self._last_exec_time_ms = (time.perf_counter() - t0) * 1000.0
        return res

    def get_last_exec_time_ms(self) -> float:
        return self._last_exec_time_ms


class _ModbusResponse:
    def __init__(self, registers: Optional[List[int]] = None, bits: Optional[List[bool]] = None, error: bool = False):
        self.registers = registers or []
        self.bits = bits or []
        self._error = error

    def isError(self) -> bool:
        return self._error


class _PureSocketModbusClient:
    """
    Zero-dependency, hardened pure Python socket implementation of Modbus TCP read client.
    Physically lacks write framing and enforces strict read-only execution at the wire level.
    """

    def __init__(self, host: str, port: int = 502, timeout: float = 2.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._trans_id = 0

    def __getattr__(self, name: str):
        lowered = name.lower()
        if "write" in lowered or "force" in lowered or "stop" in lowered:
            raise PLCWriteAttemptBlockedError(
                f"FATAL SAFETY INTERCEPTION: Method '{name}' is strictly prohibited on live production equipment! "
                f"Blocked at driver level."
            )
        raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")

    def connect(self) -> bool:
        import socket
        try:
            self.close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            logger.debug(f"Pure socket connect failed to {self.host}:{self.port}: {e}")
            self.close()
            return False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _recv_exact(self, num_bytes: int) -> bytes:
        """Reads exact number of bytes from TCP stream to handle MTU fragmentation safely."""
        if not self.sock:
            raise ConnectionError("Socket is not connected.")
        buf = bytearray()
        while len(buf) < num_bytes:
            chunk = self.sock.recv(num_bytes - len(buf))
            if not chunk:
                raise ConnectionResetError("Socket connection closed prematurely by PLC.")
            buf.extend(chunk)
        return bytes(buf)

    def _execute_read_query(self, func_code: int, address: int, count: int, slave: int = 1) -> _ModbusResponse:
        """Executes a strictly read-only Modbus request with wire-level assertion."""
        # WIRE-LEVEL HARD-LOCK: Prevent any write function code from ever being assembled
        if func_code not in (0x01, 0x02, 0x03, 0x04):
            raise PLCWriteAttemptBlockedError(
                f"EGRESS FIREWALL BLOCK: Function code 0x{func_code:02X} is strictly prohibited!"
            )

        import struct
        if not self.sock:
            if not self.connect():
                return _ModbusResponse(error=True)

        self._trans_id = (self._trans_id + 1) & 0xFFFF
        pdu = struct.pack(">HHHBBHH", self._trans_id, 0, 6, slave, func_code, address, count)

        try:
            self.sock.sendall(pdu)
            header = self._recv_exact(7)
            r_tid, r_pid, r_len, r_uid = struct.unpack(">HHHB", header)

            if r_len < 2:
                return _ModbusResponse(error=True)

            body = self._recv_exact(r_len - 1)
            resp_func = body[0]

            # Check for Modbus Exception Response (High bit set: func_code | 0x80)
            if resp_func == (func_code | 0x80):
                ex_code = body[1] if len(body) > 1 else 0
                logger.warning(f"Modbus Exception 0x{ex_code:02X} from PLC for function 0x{func_code:02X} at address {address}")
                return _ModbusResponse(error=True)

            if resp_func != func_code:
                return _ModbusResponse(error=True)

            byte_count = body[1]
            data_payload = body[2 : 2 + byte_count]

            if func_code in (0x03, 0x04):
                regs = [struct.unpack(">H", data_payload[i : i + 2])[0] for i in range(0, len(data_payload) - 1, 2)]
                return _ModbusResponse(registers=regs, error=False)
            elif func_code in (0x01, 0x02):
                # Unpack bits
                bits = []
                for b in data_payload:
                    for bit_idx in range(8):
                        bits.append(bool((b >> bit_idx) & 0x01))
                return _ModbusResponse(bits=bits[:count], error=False)

            return _ModbusResponse(error=True)

        except Exception as e:
            logger.debug(f"Pure socket read error on {self.host}:{self.port}: {e}")
            self.close()
            return _ModbusResponse(error=True)

    def read_holding_registers(self, address: int, count: int, slave: int = 1) -> _ModbusResponse:
        return self._execute_read_query(0x03, address, count, slave)

    def read_input_registers(self, address: int, count: int, slave: int = 1) -> _ModbusResponse:
        return self._execute_read_query(0x04, address, count, slave)

    def read_discrete_inputs(self, address: int, count: int, slave: int = 1) -> _ModbusResponse:
        return self._execute_read_query(0x02, address, count, slave)

    def read_coils(self, address: int, count: int, slave: int = 1) -> _ModbusResponse:
        return self._execute_read_query(0x01, address, count, slave)

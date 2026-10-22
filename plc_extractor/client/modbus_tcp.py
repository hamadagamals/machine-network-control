"""
Read-Only Modbus TCP Driver (own framing, zero third-party dependency)

Why our own driver instead of pymodbus?
  * pymodbus exposes write_register / write_coil / execute(any_request) / diag_restart...
    Any of those is one typo away from touching the machine.
  * pymodbus renamed keyword arguments between releases (slave= -> device_id=),
    which silently breaks reads after an upgrade.

This driver:
  * Has exactly ONE function that touches the socket for sending (_send_frame).
  * _send_frame re-checks the function-code byte INSIDE the final bytes before sendall().
  * Contains no code capable of assembling a write PDU.
  * Validates every response (transaction id, protocol id, unit id, function code, byte count).
  * Keeps the TCP session open on Modbus exception responses (the PLC answered correctly),
    and closes it only on real communication faults (timeouts, garbage, resets).
"""

import logging
import socket
import struct
import threading
from typing import List, Optional

from plc_extractor.client.safety import (
    MODBUS_READ_FUNCTION_CODES,
    PLCWriteAttemptBlockedError,
    assert_modbus_read_function,
)

logger = logging.getLogger("ModbusReadOnly")

MAX_REGISTERS_PER_READ = 125
MAX_BITS_PER_READ = 2000

EXCEPTION_NAMES = {
    0x01: "ILLEGAL_FUNCTION",
    0x02: "ILLEGAL_DATA_ADDRESS",
    0x03: "ILLEGAL_DATA_VALUE",
    0x04: "SERVER_DEVICE_FAILURE",
    0x05: "ACKNOWLEDGE",
    0x06: "SERVER_DEVICE_BUSY",
    0x08: "MEMORY_PARITY_ERROR",
    0x0A: "GATEWAY_PATH_UNAVAILABLE",
    0x0B: "GATEWAY_TARGET_FAILED_TO_RESPOND",
}


class ModbusExceptionResponse(IOError):
    """The device answered with a valid Modbus exception (session is still healthy)."""

    def __init__(self, function_code: int, exception_code: int, address: int, count: int):
        self.function_code = function_code
        self.exception_code = exception_code
        self.address = address
        self.count = count
        name = EXCEPTION_NAMES.get(exception_code, "UNKNOWN")
        super().__init__(
            f"Modbus exception 0x{exception_code:02X} ({name}) for FC 0x{function_code:02X} "
            f"at address {address} count {count}"
        )


class ModbusCommunicationError(ConnectionError):
    """Timeout / reset / malformed frame. The session is closed."""


class ReadOnlyModbusTCP:
    """Strictly read-only Modbus TCP client."""

    def __init__(self, host: str, port: int = 502, timeout: float = 2.0):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self._sock: Optional[socket.socket] = None
        self._tid = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ session
    @property
    def connected(self) -> bool:
        return self._sock is not None

    def connect(self) -> bool:
        with self._lock:
            return self._connect_locked()

    def _connect_locked(self) -> bool:
        self._close_locked()
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._sock = sock
            return True
        except OSError as e:
            logger.debug(f"Modbus connect failed {self.host}:{self.port}: {e}")
            self._sock = None
            return False

    def close(self) -> None:
        with self._lock:
            self._close_locked()

    def _close_locked(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # ------------------------------------------------------------------ wire
    def _send_frame(self, frame: bytes) -> None:
        """THE ONLY egress point of this driver. Re-validates the final bytes."""
        if len(frame) != 12:
            raise PLCWriteAttemptBlockedError("EGRESS FIREWALL BLOCK: unexpected Modbus frame length.")
        if frame[7] not in MODBUS_READ_FUNCTION_CODES:
            raise PLCWriteAttemptBlockedError(
                f"EGRESS FIREWALL BLOCK: function code 0x{frame[7]:02X} found in outgoing frame."
            )
        self._sock.sendall(frame)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ModbusCommunicationError("Connection closed by device.")
            buf.extend(chunk)
        return bytes(buf)

    def _transact(self, unit_id: int, function_code: int, address: int, count: int) -> bytes:
        assert_modbus_read_function(function_code)

        limit = MAX_REGISTERS_PER_READ if function_code in (0x03, 0x04) else MAX_BITS_PER_READ
        if not (0 <= address <= 0xFFFF):
            raise ValueError(f"Address out of range: {address}")
        if not (1 <= count <= limit):
            raise ValueError(f"Count out of range (1..{limit}): {count}")
        if address + count > 0x10000:
            raise ValueError("Address + count exceeds 65536.")
        if not (0 <= unit_id <= 255):
            raise ValueError(f"Unit id out of range: {unit_id}")

        with self._lock:
            if self._sock is None and not self._connect_locked():
                raise ModbusCommunicationError(f"Cannot connect to {self.host}:{self.port}")

            self._tid = (self._tid + 1) & 0xFFFF
            tid = self._tid
            frame = struct.pack(">HHHBBHH", tid, 0, 6, unit_id, function_code, address, count)

            try:
                self._send_frame(frame)
                header = self._recv_exact(7)
                r_tid, r_pid, r_len, r_uid = struct.unpack(">HHHB", header)
                if r_pid != 0:
                    raise ModbusCommunicationError(f"Invalid protocol id {r_pid}")
                if r_len < 2 or r_len > 254:
                    raise ModbusCommunicationError(f"Invalid MBAP length {r_len}")
                body = self._recv_exact(r_len - 1)
                if r_tid != tid:
                    raise ModbusCommunicationError(f"Transaction id mismatch (sent {tid}, got {r_tid})")
                if r_uid != unit_id and unit_id not in (0, 255):
                    raise ModbusCommunicationError(f"Unit id mismatch (sent {unit_id}, got {r_uid})")
            except PLCWriteAttemptBlockedError:
                raise
            except ModbusCommunicationError:
                self._close_locked()
                raise
            except OSError as e:
                self._close_locked()
                raise ModbusCommunicationError(f"Socket error: {e}") from e

        resp_fc = body[0]
        if resp_fc == (function_code | 0x80):
            ex_code = body[1] if len(body) > 1 else 0
            raise ModbusExceptionResponse(function_code, ex_code, address, count)
        if resp_fc != function_code:
            self.close()
            raise ModbusCommunicationError(f"Function code mismatch (sent {function_code}, got {resp_fc})")

        byte_count = body[1] if len(body) > 1 else -1
        expected = count * 2 if function_code in (0x03, 0x04) else (count + 7) // 8
        if byte_count != expected or len(body) != 2 + byte_count:
            self.close()
            raise ModbusCommunicationError(
                f"Byte count mismatch (expected {expected}, header {byte_count}, payload {len(body) - 2})"
            )
        return body[2:]

    # ------------------------------------------------------------------ public reads
    def read_holding_registers(self, address: int, count: int, unit_id: int = 1) -> List[int]:
        data = self._transact(unit_id, 0x03, address, count)
        return list(struct.unpack(f">{count}H", data))

    def read_input_registers(self, address: int, count: int, unit_id: int = 1) -> List[int]:
        data = self._transact(unit_id, 0x04, address, count)
        return list(struct.unpack(f">{count}H", data))

    def read_coils(self, address: int, count: int, unit_id: int = 1) -> List[bool]:
        return self._unpack_bits(self._transact(unit_id, 0x01, address, count), count)

    def read_discrete_inputs(self, address: int, count: int, unit_id: int = 1) -> List[bool]:
        return self._unpack_bits(self._transact(unit_id, 0x02, address, count), count)

    @staticmethod
    def _unpack_bits(data: bytes, count: int) -> List[bool]:
        bits: List[bool] = []
        for byte in data:
            for i in range(8):
                bits.append(bool((byte >> i) & 1))
        return bits[:count]

    def _execute_read_query(self, func_code: int, address: int, count: int, slave: int = 1):
        assert_modbus_read_function(func_code)
        return self._transact(slave, func_code, address, count)

    def __getattr__(self, name: str):
        from plc_extractor.client.safety import is_forbidden_name
        if is_forbidden_name(name):
            raise PLCWriteAttemptBlockedError(
                f"FATAL SAFETY INTERCEPTION: '{name}' is strictly prohibited on production equipment."
            )
        raise AttributeError(f"'ReadOnlyModbusTCP' has no attribute '{name}'")


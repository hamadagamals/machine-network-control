"""
STRICTLY READ-ONLY PLC CLIENT (ZERO WRITE CAPABILITY)

Design (hardened after self-audit):
  1. NO generic proxy. The previous version forwarded any unknown attribute to the
     underlying library (pymodbus/snap7/pycomm3), which leaked execute(), generic_message(),
     diag_restart_communication(), set_plc_datetime() ... That proxy is gone.
  2. The underlying driver is held in a private slot and is never returned to callers.
  3. Only explicitly whitelisted READ methods exist on this class.
  4. Modbus uses our own driver (modbus_tcp.py) whose wire frame is re-checked before send.
  5. Unknown / unsupported protocols FAIL to connect (no fake "connected" state).
"""

import logging
import time
from typing import Any, Dict, List, Optional, Union

from plc_extractor.client.rate_limiter import PLCRateLimiter
from plc_extractor.client.safety import PLCWriteAttemptBlockedError, is_forbidden_name
from plc_extractor.client.modbus_tcp import (
    ReadOnlyModbusTCP,
    ModbusExceptionResponse,
    ModbusCommunicationError,
)

logger = logging.getLogger("PLCReadOnlyClient")

SUPPORTED_PROTOCOLS = ("modbus_tcp", "s7comm", "ethernet_ip", "opcua")

# Backwards compatibility alias
_PureSocketModbusClient = ReadOnlyModbusTCP

__all__ = [
    "ReadOnlyPLCClient",
    "ReadOnlyModbusTCP",
    "_PureSocketModbusClient",
    "PLCWriteAttemptBlockedError",
    "ModbusExceptionResponse",
    "ModbusCommunicationError",
    "SUPPORTED_PROTOCOLS",
]


class ReadOnlyPLCClient:
    """Safety wrapper exposing read-only operations only."""

    __slots__ = (
        "protocol", "host", "port", "options", "rate_limiter",
        "_ReadOnlyPLCClient__driver", "_ReadOnlyPLCClient__connected",
        "last_error", "_last_exec_time_ms",
    )

    def __init__(
        self,
        protocol: str,
        host: str,
        port: int = 502,
        options: Optional[Dict[str, Any]] = None,
        max_requests_per_second: float = 50.0,
    ):
        self.protocol = (protocol or "").lower().strip()
        self.host = host
        self.port = int(port)
        self.options = dict(options or {})
        self.rate_limiter = PLCRateLimiter(max_requests_per_second=max_requests_per_second)
        self.__driver = None
        self.__connected = False
        self.last_error: str = ""
        self._last_exec_time_ms = 0.0
        logger.info(
            f"[SAFETY LOCK ENGAGED] ReadOnlyPLCClient {self.protocol}://{self.host}:{self.port} "
            f"(max {max_requests_per_second} req/s)"
        )

    # ------------------------------------------------------------------ hard block
    def __getattr__(self, name: str):
        # Only called for attributes that do NOT exist on this class.
        if is_forbidden_name(name):
            msg = (f"FATAL SAFETY INTERCEPTION: '{name}' is prohibited on production equipment. "
                   f"Blocked before any network activity.")
            logger.critical(msg)
            raise PLCWriteAttemptBlockedError(msg)
        raise AttributeError(f"'ReadOnlyPLCClient' has no attribute '{name}' (no pass-through to drivers).")

    # ------------------------------------------------------------------ session
    def connect(self) -> bool:
        self.disconnect()
        self.last_error = ""
        try:
            if self.protocol == "modbus_tcp":
                drv = ReadOnlyModbusTCP(self.host, self.port, timeout=self.options.get("timeout", 2.0))
                self.__connected = drv.connect()
                self.__driver = drv
                if not self.__connected:
                    self.last_error = f"TCP connection to {self.host}:{self.port} failed."

            elif self.protocol == "s7comm":
                try:
                    import snap7  # noqa: F401
                except ImportError:
                    self.last_error = "DRIVER_MISSING: python-snap7 is not installed (pip install python-snap7)."
                    return False
                import snap7
                drv = snap7.client.Client()
                drv.connect(self.host, int(self.options.get("rack", 0)), int(self.options.get("slot", 1)), self.port)
                self.__connected = bool(drv.get_connected())
                self.__driver = drv

            elif self.protocol == "ethernet_ip":
                try:
                    from pycomm3 import LogixDriver
                except ImportError:
                    self.last_error = "DRIVER_MISSING: pycomm3 is not installed (pip install pycomm3)."
                    return False
                route = self.options.get("route_path")
                path = f"{self.host}/{route}" if route else self.host
                drv = LogixDriver(path, init_tags=True)
                drv.open()  # Forward Open + identity + tag list upload (all reads)
                self.__connected = bool(drv.connected)
                self.__driver = drv

            elif self.protocol == "opcua":
                try:
                    from asyncua.sync import Client as OpcClient
                except ImportError:
                    self.last_error = "DRIVER_MISSING: asyncua is not installed (pip install asyncua)."
                    return False
                url = self.options.get("url") or f"opc.tcp://{self.host}:{self.port}"
                drv = OpcClient(url, timeout=self.options.get("timeout", 4))
                if self.options.get("username"):
                    drv.set_user(self.options["username"])
                    drv.set_password(self.options.get("password", ""))
                drv.connect()
                self.__connected = True
                self.__driver = drv

            else:
                self.last_error = f"UNSUPPORTED_PROTOCOL: '{self.protocol}'."
                self.__connected = False

        except Exception as e:  # driver-specific connection failures
            self.last_error = f"{type(e).__name__}: {e}"
            self.__connected = False

        if self.__connected:
            logger.info(f"Connected (READ-ONLY) to {self.protocol}://{self.host}:{self.port}")
        else:
            logger.error(f"Connection failed {self.protocol}://{self.host}:{self.port}: {self.last_error}")
        return self.__connected

    def is_connected(self) -> bool:
        if self.protocol == "modbus_tcp" and self.__driver is not None:
            return self.__driver.connected
        return self.__connected

    def disconnect(self) -> None:
        drv = self.__driver
        self.__driver = None
        self.__connected = False
        if drv is None:
            return
        try:
            if self.protocol == "modbus_tcp":
                drv.close()
            elif self.protocol == "s7comm":
                drv.disconnect()
            elif self.protocol == "ethernet_ip":
                drv.close()
            elif self.protocol == "opcua":
                drv.disconnect()
        except Exception as e:
            logger.debug(f"Disconnect error: {e}")

    def _require(self, proto: str):
        if self.protocol != proto:
            raise TypeError(f"Operation requires protocol '{proto}', client is '{self.protocol}'.")
        if self.__driver is None:
            if proto == "modbus_tcp":
                # Allow lazy reconnect for Modbus only (own driver reconnects safely)
                self.__driver = ReadOnlyModbusTCP(self.host, self.port, timeout=self.options.get("timeout", 2.0))
            else:
                raise ConnectionError("PLC client not connected.")
        return self.__driver

    def _timed(self, fn, *args):
        self.rate_limiter.acquire()
        t0 = time.perf_counter()
        try:
            return fn(*args)
        finally:
            self._last_exec_time_ms = (time.perf_counter() - t0) * 1000.0

    def get_last_exec_time_ms(self) -> float:
        return self._last_exec_time_ms

    # ------------------------------------------------------------------ Modbus (FC 01-04 only)
    def read_holding_registers(self, address: int, count: int, unit_id: int = 1) -> List[int]:
        drv = self._require("modbus_tcp")
        return self._timed(drv.read_holding_registers, address, count, unit_id)

    def read_input_registers(self, address: int, count: int, unit_id: int = 1) -> List[int]:
        drv = self._require("modbus_tcp")
        return self._timed(drv.read_input_registers, address, count, unit_id)

    def read_coils(self, address: int, count: int, unit_id: int = 1) -> List[bool]:
        drv = self._require("modbus_tcp")
        return self._timed(drv.read_coils, address, count, unit_id)

    def read_discrete_inputs(self, address: int, count: int, unit_id: int = 1) -> List[bool]:
        drv = self._require("modbus_tcp")
        return self._timed(drv.read_discrete_inputs, address, count, unit_id)

    # ------------------------------------------------------------------ Siemens S7 (read services only)
    def read_s7_db(self, db_number: int, start: int, size: int) -> bytearray:
        drv = self._require("s7comm")
        return bytearray(self._timed(drv.db_read, int(db_number), int(start), int(size)))

    def read_s7_area(self, area: str, db_number: int, start: int, size: int) -> bytearray:
        """area in {'DB','MK','PE','PA'} -> data blocks, merkers, process inputs, process outputs (READ)."""
        drv = self._require("s7comm")
        try:
            from snap7.types import Areas  # python-snap7 1.x
        except ImportError:
            from snap7.type import Areas   # python-snap7 2.x
        area_map = {"DB": Areas.DB, "MK": Areas.MK, "PE": Areas.PE, "PA": Areas.PA}
        if area not in area_map:
            raise ValueError(f"Unsupported S7 area '{area}'")
        return bytearray(self._timed(drv.read_area, area_map[area], int(db_number), int(start), int(size)))

    def get_s7_identity(self) -> Dict[str, Any]:
        """SZL reads only (CPU info / order code / run state)."""
        drv = self._require("s7comm")
        info: Dict[str, Any] = {}
        for key, fn in (("cpu_info", drv.get_cpu_info), ("order_code", drv.get_order_code),
                        ("cpu_state", drv.get_cpu_state), ("pdu_length", drv.get_pdu_length)):
            try:
                val = self._timed(fn)
                if key == "cpu_info":
                    info["module_type"] = _bstr(getattr(val, "ModuleTypeName", ""))
                    info["serial_number"] = _bstr(getattr(val, "SerialNumber", ""))
                    info["module_name"] = _bstr(getattr(val, "ModuleName", ""))
                    info["as_name"] = _bstr(getattr(val, "ASName", ""))
                elif key == "order_code":
                    info["order_code"] = _bstr(getattr(val, "OrderCode", getattr(val, "Code", "")))
                    v1, v2, v3 = getattr(val, "V1", None), getattr(val, "V2", None), getattr(val, "V3", None)
                    if v1 is not None:
                        info["firmware_version"] = f"V{v1}.{v2}.{v3}"
                else:
                    info[key] = str(val)
            except Exception as e:
                info[f"{key}_error"] = str(e)
        return info

    def list_s7_blocks(self) -> Dict[str, Any]:
        drv = self._require("s7comm")
        blocks = self._timed(drv.list_blocks)
        return {k: getattr(blocks, k) for k in ("OBCount", "FBCount", "FCCount", "SFBCount", "SFCCount", "DBCount", "SDBCount") if hasattr(blocks, k)}

    # ------------------------------------------------------------------ EtherNet/IP (reads only)
    def read_cip_tags(self, tags: Union[str, List[str]]) -> Any:
        drv = self._require("ethernet_ip")
        return self._timed(drv.read, *([tags] if isinstance(tags, str) else tags))

    def list_cip_tags(self) -> List[Dict[str, Any]]:
        drv = self._require("ethernet_ip")
        out = []
        for name, meta in (getattr(drv, "tags", {}) or {}).items():
            out.append({
                "name": name,
                "data_type": str(meta.get("data_type_name") or meta.get("data_type")),
                "dimensions": meta.get("dimensions"),
            })
        return out

    def get_cip_identity(self) -> Dict[str, Any]:
        drv = self._require("ethernet_ip")
        return dict(getattr(drv, "info", {}) or {})

    # ------------------------------------------------------------------ OPC UA (browse + read only)
    def browse_opcua_variables(self, max_nodes: int = 1500, max_depth: int = 6) -> List[Dict[str, Any]]:
        drv = self._require("opcua")
        from asyncua import ua
        results: List[Dict[str, Any]] = []
        stack = [(drv.nodes.objects, "Objects", 0)]
        seen = set()
        while stack and len(results) < max_nodes:
            node, path, depth = stack.pop()
            try:
                children = self._timed(node.get_children)
            except Exception:
                continue
            for child in children:
                nid = child.nodeid.to_string()
                if nid in seen:
                    continue
                seen.add(nid)
                try:
                    bname = self._timed(child.read_browse_name).Name
                    nclass = self._timed(child.read_node_class)
                except Exception:
                    continue
                cpath = f"{path}/{bname}"
                if nclass == ua.NodeClass.Variable:
                    entry = {"node_id": nid, "browse_path": cpath}
                    try:
                        dv = self._timed(child.read_data_value)
                        entry["value"] = _jsonable(dv.Value.Value)
                        entry["data_type"] = dv.Value.VariantType.name
                    except Exception as e:
                        entry["read_error"] = str(e)
                    results.append(entry)
                if nclass in (ua.NodeClass.Object, ua.NodeClass.Variable) and depth + 1 < max_depth \
                        and not cpath.startswith("Objects/Server"):
                    stack.append((child, cpath, depth + 1))
        return results

    def read_opcua_nodes(self, node_ids: List[str]) -> Dict[str, Any]:
        drv = self._require("opcua")
        out = {}
        for nid in node_ids:
            try:
                out[nid] = _jsonable(self._timed(drv.get_node(nid).read_value))
            except Exception as e:
                out[nid] = None
                logger.debug(f"OPC UA read {nid} failed: {e}")
        return out


def _bstr(v: Any) -> str:
    if isinstance(v, (bytes, bytearray)):
        return v.decode("ascii", errors="ignore").strip("\x00 ").strip()
    return str(v).strip()


def _jsonable(v: Any) -> Any:
    if isinstance(v, (int, float, bool, str)) or v is None:
        return v
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v[:50]]
    return str(v)

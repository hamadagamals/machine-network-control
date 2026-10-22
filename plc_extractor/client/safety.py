"""
Central Safety Definitions (Strict Read-Only Policy)

Every driver in this project imports its safety primitives from here so the
policy is defined in exactly one place.

Policy:
  * Modbus: ONLY function codes 0x01, 0x02, 0x03, 0x04 may ever be put on the wire.
    (0x2B / MEI was deliberately removed: MEI type 0x0D can carry writes.)
  * Siemens S7: ONLY read services are wrapped (db_read / read_area / SZL identity reads).
  * EtherNet/IP: ONLY tag reads + tag list upload.
  * OPC UA: ONLY browse + read attribute services.
  No write, force, download, delete, CPU start/stop, time-set, diagnostics-restart,
  or generic/raw service call is exposed anywhere.
"""

from typing import FrozenSet

# The ONLY Modbus function codes allowed on the wire.
MODBUS_READ_FUNCTION_CODES: FrozenSet[int] = frozenset({0x01, 0x02, 0x03, 0x04})

# Names that must never be resolvable on any client object in this project.
FORBIDDEN_NAME_FRAGMENTS = (
    "write", "force", "stop", "start", "download", "delete", "reset",
    "execute", "generic_message", "set_", "call_method", "restart",
    "clear", "compress", "copy_ram", "password",
)


class PLCWriteAttemptBlockedError(PermissionError):
    """Raised immediately when anything attempts to mutate PLC memory or state."""


def assert_modbus_read_function(function_code: int) -> None:
    """Hard gate: raises unless the function code is a pure read."""
    if function_code not in MODBUS_READ_FUNCTION_CODES:
        raise PLCWriteAttemptBlockedError(
            f"EGRESS FIREWALL BLOCK: Modbus function code 0x{function_code:02X} is prohibited. "
            f"Only read codes {sorted(hex(c) for c in MODBUS_READ_FUNCTION_CODES)} are permitted."
        )


def is_forbidden_name(name: str) -> bool:
    lowered = name.lower()
    return any(fragment in lowered for fragment in FORBIDDEN_NAME_FRAGMENTS)

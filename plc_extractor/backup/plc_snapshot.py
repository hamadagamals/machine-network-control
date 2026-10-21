"""
PLC Memory & Tag Schema Read-Only Backup Utility
Safely snapshots active PLC data blocks, tag lists, UDTs, and setpoints
for disaster recovery and offline symbol analysis without disturbing execution.
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
from plc_extractor.client.readonly_wrapper import ReadOnlyPLCClient

logger = logging.getLogger("PLCSnapshot")


class PLCSnapshot:
    """
    Performs non-intrusive, read-only extraction of PLC memory structures and recipes.
    """

    def __init__(self, client: ReadOnlyPLCClient, output_dir: str = "data/snapshots"):
        self.client = client
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def backup_s7(self) -> Dict[str, Any]:
        """Backs up Siemens S7 blocks and Data Block (DB) contents."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        snapshot_meta: Dict[str, Any] = {
            "protocol": "s7comm",
            "host": self.client.host,
            "timestamp": timestamp,
            "blocks": [],
            "db_dumps": {},
        }

        try:
            raw = self.client._raw_client
            if not raw or not self.client.is_connected():
                raise ConnectionError("S7 Client not connected.")

            # Check protection status (SZL read-only)
            try:
                prot = raw.get_protection()
                snapshot_meta["protection_level"] = str(prot)
            except Exception as e:
                logger.debug(f"Could not read S7 protection: {e}")

            # Enumerate blocks
            try:
                blocks = raw.list_blocks()
                snapshot_meta["blocks"] = [str(b) for b in blocks]
                logger.info(f"Enumerated {len(snapshot_meta['blocks'])} S7 blocks.")
            except Exception as e:
                logger.warning(f"list_blocks not supported or restricted: {e}")

            # Attempt DB snapshot for candidate DBs (e.g., DB1 to DB20)
            db_dir = os.path.join(self.output_dir, f"s7_dbs_{timestamp}")
            os.makedirs(db_dir, exist_ok=True)

            for db_num in range(1, 21):
                try:
                    # Read first 128 bytes of DB
                    db_bytes = self.client.read_s7_db(db_num, start=0, size=128)
                    bin_file = os.path.join(db_dir, f"DB{db_num}.bin")
                    with open(bin_file, "wb") as f:
                        f.write(db_bytes)
                    snapshot_meta["db_dumps"][f"DB{db_num}"] = {
                        "size_bytes": len(db_bytes),
                        "file": bin_file,
                    }
                except Exception:
                    continue  # DB does not exist, skip silently

            # Write summary JSON
            meta_file = os.path.join(self.output_dir, f"s7_snapshot_{timestamp}.json")
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(snapshot_meta, f, indent=2)

            logger.info(f"Siemens S7 Snapshot complete -> {meta_file}")
            return snapshot_meta

        except Exception as e:
            logger.error(f"S7 snapshot failed: {e}")
            raise

    def backup_rockwell(self) -> Dict[str, Any]:
        """Backs up Allen-Bradley ControlLogix/CompactLogix Tag dictionary and UDTs."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        snapshot_meta: Dict[str, Any] = {
            "protocol": "ethernet_ip",
            "host": self.client.host,
            "timestamp": timestamp,
            "tags": [],
            "udts": {},
        }

        try:
            raw = self.client._raw_client
            if hasattr(raw, "get_tag_list"):
                tag_list = raw.get_tag_list()
                snapshot_meta["tags"] = [str(t) for t in tag_list]
                logger.info(f"Discovered {len(snapshot_meta['tags'])} Logix tags.")

            if hasattr(raw, "udt"):
                snapshot_meta["udts"] = {k: str(v) for k, v in raw.udt.items()}

            meta_file = os.path.join(self.output_dir, f"rockwell_tags_{timestamp}.json")
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(snapshot_meta, f, indent=2)

            logger.info(f"Rockwell Tag Snapshot complete -> {meta_file}")
            return snapshot_meta

        except Exception as e:
            logger.error(f"Rockwell backup failed: {e}")
            raise

    def backup_modbus(self, max_registers: int = 500, unit_id: int = 1) -> Dict[str, Any]:
        """Backs up Modbus holding registers in contiguous blocks."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        registers_dump: Dict[int, int] = {}

        # Read in blocks of 50 to avoid PDU overflow
        block_size = 50
        for start in range(0, max_registers, block_size):
            try:
                chunk = self.client.read_holding_registers(address=start, count=block_size, unit_id=unit_id)
                for offset, val in enumerate(chunk):
                    registers_dump[start + offset] = val
            except Exception as e:
                logger.debug(f"Block read stopped at address {start}: {e}")
                break

        snapshot_meta = {
            "protocol": "modbus_tcp",
            "host": self.client.host,
            "unit_id": unit_id,
            "timestamp": timestamp,
            "total_registers_read": len(registers_dump),
            "registers": registers_dump,
        }

        meta_file = os.path.join(self.output_dir, f"modbus_snapshot_{timestamp}.json")
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(snapshot_meta, f, indent=2)

        logger.info(f"Modbus Snapshot complete ({len(registers_dump)} registers) -> {meta_file}")
        return snapshot_meta

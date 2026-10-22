"""
High-Frequency Drift-Compensated Polling Engine
Coordinates multi-tiered polling intervals with the PLC scan cycle using
monotonic drift compensation and non-blocking decoupled buffering.
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from plc_extractor.client.readonly_wrapper import ReadOnlyPLCClient
from plc_extractor.acquisition.storage_engine import StorageEngine

logger = logging.getLogger("PLCPoller")


class TieredPoller:
    """
    Precision Multi-Tier Poller.
    T1: High-Frequency (20-100ms) - Motion, State, Cycle Trigger, High-speed Pressures.
    T2: Medium-Frequency (1s)      - Process Temperatures, Levels, Line Speeds.
    T3: Low-Frequency (10s)       - Shift Counters, Recipe IDs, Diagnostics.
    """

    def __init__(
        self,
        client: ReadOnlyPLCClient,
        storage: StorageEngine,
        tier1_interval_ms: int = 50,
        tier2_interval_ms: int = 1000,
        tier3_interval_ms: int = 10000,
        unit_id: int = 1,
        tags_config: Optional[Dict[str, Any]] = None,
        telemetry_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.client = client
        self.storage = storage
        self.t1_interval = max(0.01, tier1_interval_ms / 1000.0)
        self.t2_interval = max(0.1, tier2_interval_ms / 1000.0)
        self.t3_interval = max(1.0, tier3_interval_ms / 1000.0)
        self.unit_id = unit_id
        self.tags_config = tags_config or {}
        self.callback = telemetry_callback

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._metrics = {
            "poll_cycles": 0,
            "avg_latency_ms": 0.0,
            "overruns": 0,
        }

    @staticmethod
    def _to_int16(val: int) -> int:
        return val - 65536 if val > 32767 else val

    def start(self):
        """Starts the high-frequency polling engine."""
        if not self.client.is_connected():
            if not self.client.connect():
                raise ConnectionError("Cannot start poller: PLC connection failed.")

        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info(
            f"Poller started. T1: {self.t1_interval*1000:.1f}ms, "
            f"T2: {self.t2_interval*1000:.1f}ms, T3: {self.t3_interval*1000:.1f}ms, Unit ID: {self.unit_id}"
        )

    def stop(self):
        """Stops the poller."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("Poller stopped.")

    def _run_loop(self):
        """Precision drift-compensated polling loop."""
        import struct
        from plc_extractor.client.modbus_tcp import ModbusExceptionResponse, ModbusCommunicationError

        next_tick = time.perf_counter()
        last_t2 = 0.0
        last_t3 = 0.0

        latencies = []

        while self._running:
            t_start = time.perf_counter()
            host_utc = time.time()
            now_perf = t_start

            record = {
                "host_timestamp": host_utc,
                "monotonic_ns": time.perf_counter_ns(),
                "latency_ms": 0.0,
            }

            try:
                # --------------------------------------------------------------
                # 1. Tier 1: High-Frequency Read (Contiguous Block Batching)
                # --------------------------------------------------------------
                if self.client.protocol == "modbus_tcp":
                    # Batch read holding registers 0 to 19 (Single PDU)
                    regs = self.client.read_holding_registers(address=0, count=20, unit_id=self.unit_id)
                    record.update({
                        "machine_state": regs[0],
                        "cycle_trigger": regs[1],
                        "hydraulic_pressure_bar": round(self._to_int16(regs[2]) / 10.0, 2),
                        "motor_current_amps": round(self._to_int16(regs[3]) / 10.0, 2),
                        "position_encoder": (regs[4] << 16) | regs[5],
                    })
                elif self.client.protocol == "s7comm":
                    # Batch read DB1 bytes 0 to 32
                    db_bytes = self.client.read_s7_db(db_number=1, start=0, size=32)
                    record["raw_db1_len"] = len(db_bytes)
                    if len(db_bytes) >= 8:
                        state_val = struct.unpack(">h", db_bytes[0:2])[0]
                        trig_val = 1 if (db_bytes[2] & 0x01) else 0
                        press_val = struct.unpack(">h", db_bytes[4:6])[0] / 10.0
                        curr_val = struct.unpack(">h", db_bytes[6:8])[0] / 10.0
                        record.update({
                            "machine_state": state_val,
                            "cycle_trigger": trig_val,
                            "hydraulic_pressure_bar": round(press_val, 2),
                            "motor_current_amps": round(curr_val, 2),
                        })
                else:
                    record["heartbeat"] = 1

                # --------------------------------------------------------------
                # 2. Tier 2: Medium-Frequency Read
                # --------------------------------------------------------------
                if (now_perf - last_t2) >= self.t2_interval:
                    if self.client.protocol == "modbus_tcp":
                        t2_regs = self.client.read_holding_registers(address=20, count=5, unit_id=self.unit_id)
                        record.update({
                            "oil_temperature_c": round(self._to_int16(t2_regs[0]) / 10.0, 1),
                            "tank_level_percent": round(t2_regs[1] / 10.0, 1),
                        })
                    elif self.client.protocol == "s7comm" and "raw_db1_len" in record and record["raw_db1_len"] >= 22:
                        temp_val = struct.unpack(">h", db_bytes[20:22])[0] / 10.0
                        record["oil_temperature_c"] = round(temp_val, 1)
                    last_t2 = now_perf

                # --------------------------------------------------------------
                # 3. Tier 3: Low-Frequency Read
                # --------------------------------------------------------------
                if (now_perf - last_t3) >= self.t3_interval:
                    if self.client.protocol == "modbus_tcp":
                        t3_regs = self.client.read_holding_registers(address=30, count=5, unit_id=self.unit_id)
                        record.update({
                            "shift_part_counter": (t3_regs[0] << 16) | t3_regs[1],
                            "active_recipe_id": t3_regs[2],
                        })
                    elif self.client.protocol == "s7comm" and "raw_db1_len" in record and record["raw_db1_len"] >= 28:
                        counter_val = struct.unpack(">i", db_bytes[24:28])[0]
                        record["shift_part_counter"] = counter_val
                    last_t3 = now_perf

                # Calculate latency
                t_end = time.perf_counter()
                latency_ms = (t_end - t_start) * 1000.0
                record["latency_ms"] = round(latency_ms, 2)
                latencies.append(latency_ms)
                if len(latencies) > 100:
                    latencies.pop(0)

                # Ingest into decoupled storage queue
                self.storage.ingest(record)

                # Optional live callback (for WebSockets / Dashboard)
                if self.callback:
                    try:
                        self.callback(record)
                    except Exception:
                        pass

                self._metrics["poll_cycles"] += 1
                self._metrics["avg_latency_ms"] = round(sum(latencies) / len(latencies), 2)

            except ModbusExceptionResponse as e:
                # Modbus logical exception (e.g. Illegal Data Address): PLC socket is ALIVE and healthy.
                # Do NOT drop/reconnect socket to avoid exhausting PLC socket pool.
                logger.debug(f"Modbus logical exception received from PLC: {e}")
            except Exception as e:
                # Transport / socket connection breakdown
                logger.warning(f"Polling socket error: {e}. Attempting safe reconnection in 1.0s...")
                time.sleep(1.0)
                try:
                    self.client.disconnect()
                    self.client.connect()
                except Exception:
                    pass
                next_tick = time.perf_counter()

            # ------------------------------------------------------------------
            # DRIFT-COMPENSATED MONOTONIC SLEEP
            # ------------------------------------------------------------------
            next_tick += self.t1_interval
            sleep_time = next_tick - time.perf_counter()
            if sleep_time > 0:
                time.sleep(sleep_time)
            else:
                self._metrics["overruns"] += 1
                # If behind schedule by more than 2 cycles, reset tick to prevent runaway burst
                if abs(sleep_time) > (2 * self.t1_interval):
                    next_tick = time.perf_counter()

    def get_metrics(self) -> Dict[str, Any]:
        return dict(self._metrics)

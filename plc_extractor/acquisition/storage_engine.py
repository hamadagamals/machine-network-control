"""
High-Performance Decoupled Telemetry Storage Engine
Buffers high-frequency industrial telemetry in memory and streams to DuckDB / Parquet
without blocking the real-time polling thread.
"""

import logging
import os
import queue
import threading
import time
from typing import Any, Dict, List, Optional
import pandas as pd

logger = logging.getLogger("StorageEngine")


class StorageEngine:
    """
    Decoupled Consumer thread for high-frequency telemetry data.
    Flushes batches to DuckDB and partitioned Parquet files.
    """

    def __init__(
        self,
        db_path: str = "data/telemetry/machine_telemetry.duckdb",
        parquet_dir: str = "data/telemetry/parquet",
        flush_interval_seconds: float = 10.0,
        max_queue_size: int = 50000,
    ):
        self.db_path = db_path
        self.parquet_dir = parquet_dir
        self.flush_interval = flush_interval_seconds
        
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        os.makedirs(parquet_dir, exist_ok=True)

        self.queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._running = False
        self._consumer_thread: Optional[threading.Thread] = None
        self._buffer: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._total_records_saved = 0

    def start(self):
        """Starts the background disk writer thread."""
        self._running = True
        self._consumer_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._consumer_thread.start()
        logger.info(f"Storage Engine started. Streaming to DuckDB: {self.db_path}")

    def stop(self):
        """Stops writer and flushes remaining records."""
        self._running = False
        if self._consumer_thread and self._consumer_thread.is_alive():
            self._consumer_thread.join(timeout=3.0)
        self._flush_buffer_to_disk()
        logger.info(f"Storage Engine stopped. Total records saved: {self._total_records_saved}")

    def ingest(self, record: Dict[str, Any]):
        """Non-blocking record enqueue from the high-frequency polling thread."""
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            logger.warning("Telemetry queue full! Dropping oldest record to preserve polling stability.")
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(record)
            except Exception:
                pass

    def _worker_loop(self):
        last_flush = time.perf_counter()
        while self._running:
            try:
                record = self.queue.get(timeout=0.1)
                with self._lock:
                    self._buffer.append(record)
                self.queue.task_done()
            except queue.Empty:
                pass

            now = time.perf_counter()
            if (now - last_flush) >= self.flush_interval or len(self._buffer) >= 5000:
                self._flush_buffer_to_disk()
                last_flush = now

    def _flush_buffer_to_disk(self):
        """Flushes buffered records to DuckDB and Parquet."""
        with self._lock:
            if not self._buffer:
                return
            records_to_write = list(self._buffer)
            self._buffer.clear()

        try:
            df = pd.DataFrame(records_to_write)
            if df.empty:
                return

            self._total_records_saved += len(df)

            # 1. Append to DuckDB
            try:
                import duckdb
                con = duckdb.connect(self.db_path)
                con.execute("CREATE TABLE IF NOT EXISTS telemetry AS SELECT * FROM df WHERE 1=0;")
                con.register("temp_df", df)
                con.execute("INSERT INTO telemetry SELECT * FROM temp_df;")
                con.close()
            except ImportError:
                # Fallback to appending to CSV
                csv_path = self.db_path.replace(".duckdb", ".csv")
                df.to_csv(csv_path, mode="a", index=False, header=not os.path.exists(csv_path))

            # 2. Export partitioned Parquet hourly
            hour_str = time.strftime("%Y%m%d_%H")
            parquet_file = os.path.join(self.parquet_dir, f"telemetry_{hour_str}.parquet")
            try:
                df.to_parquet(parquet_file, engine="pyarrow", index=False)
            except Exception as e:
                logger.debug(f"Parquet export skipped: {e}")

            logger.debug(f"Flushed {len(df)} telemetry records to storage.")

        except Exception as e:
            logger.error(f"Error flushing telemetry buffer: {e}")

    def query_recent(self, limit: int = 100) -> pd.DataFrame:
        """Queries recent records for dashboard or analysis."""
        try:
            import duckdb
            con = duckdb.connect(self.db_path, read_only=True)
            res = con.execute(f"SELECT * FROM telemetry ORDER BY host_timestamp DESC LIMIT {limit}").fetchdf()
            con.close()
            return res
        except Exception:
            return pd.DataFrame()

import os
import sys
import time

sys.path.insert(0, os.path.abspath("."))
from plc_extractor.simulator.mock_plc_server import MockIndustrialMachinePLC
from plc_extractor.client.readonly_wrapper import ReadOnlyPLCClient
from plc_extractor.acquisition.storage_engine import StorageEngine
from plc_extractor.acquisition.poller import TieredPoller
from plc_extractor.analytics.cycle_analyzer import CycleAnalyzer

print("1. Starting Mock PLC Server on port 5025...")
server = MockIndustrialMachinePLC(host="127.0.0.1", port=5025)
server.start()
time.sleep(0.5)

print("2. Connecting ReadOnlyPLCClient...")
client = ReadOnlyPLCClient(protocol="modbus_tcp", host="127.0.0.1", port=5025)
assert client.connect()

print("3. Reading registers 0..19 (Modbus 0x03)...")
regs = client.read_holding_registers(address=0, count=20, unit_id=1)
print(f"   Read Success! Registers 0..5: {regs[:6]}")
assert len(regs) == 20

print("4. Testing storage and poller...")
storage = StorageEngine(
    db_path="data/telemetry/test_telemetry.duckdb",
    parquet_dir="data/telemetry/parquet",
)
storage.start()

poller = TieredPoller(
    client=client,
    storage=storage,
    tier1_interval_ms=50,
)
poller.start()

print("5. Polling for 2 seconds...")
time.sleep(2.0)

metrics = poller.get_metrics()
print(f"   Poller Metrics: {metrics}")
assert metrics["poll_cycles"] >= 20, f"Expected at least 20 polls, got {metrics['poll_cycles']}"

poller.stop()
storage.stop()
client.disconnect()
server.stop()

print("PIPELINE INTEGRATION TEST COMPLETED SUCCESSFULLY!")

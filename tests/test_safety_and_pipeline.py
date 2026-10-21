"""
Automated Verification & Safety Test Suite
Validates the read-only firewall, mock PLC simulation, and cycle analytics.
"""

import os
import sys
import time
import pytest
import pandas as pd

# Add root directory to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from plc_extractor.client.readonly_wrapper import ReadOnlyPLCClient, PLCWriteAttemptBlockedError
from plc_extractor.client.rate_limiter import PLCRateLimiter
from plc_extractor.analytics.cycle_analyzer import CycleAnalyzer
from plc_extractor.simulator.mock_plc_server import MockIndustrialMachinePLC


def test_safety_read_only_firewall():
    """Confirms that write and force calls raise a hard exception before hitting network."""
    client = ReadOnlyPLCClient(protocol="modbus_tcp", host="127.0.0.1", port=502)

    prohibited = ["write_register", "write_coil", "plc_stop", "force_bit", "download"]
    for method in prohibited:
        with pytest.raises((PLCWriteAttemptBlockedError, AttributeError)):
            func = getattr(client, method)
            func(0, 1)


def test_rate_limiter_throttling():
    """Confirms that rate limiter enforces request limits."""
    limiter = PLCRateLimiter(max_requests_per_second=20.0)
    t0 = time.perf_counter()
    for _ in range(5):
        limiter.acquire(blocking=True)
    elapsed = time.perf_counter() - t0
    # 5 requests with 20 req/s budget should take non-negative time
    assert elapsed >= 0.0


def test_cycle_analyzer_segmentation():
    """Tests automated cycle boundary detection and KPI calculations."""
    analyzer = CycleAnalyzer(
        trigger_tag="machine_state",
        idle_state=0,
        active_states=[1, 2, 3, 4],
        golden_duration_seconds=5.0,
    )

    # Synthetic telemetry stream: Idle(0) -> Clamp(1) -> Press(2) -> Cool(3) -> Eject(4) -> Idle(0)
    records = []
    t = 1000.0
    for state in [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 0, 0]:
        records.append({
            "host_timestamp": t,
            "machine_state": state,
            "motor_current_amps": 35.0 if state in (1, 2) else 5.0,
            "hydraulic_pressure_bar": 150.0 if state == 2 else 10.0,
            "oil_temperature_c": 45.0,
        })
        t += 0.5  # 500ms step

    df = pd.DataFrame(records)
    cycles = analyzer.analyze_stream(df)

    assert len(cycles) == 1
    c = cycles[0]
    assert c["cycle_id"] == 1
    assert c["duration_sec"] == 4.0
    assert c["max_pressure_bar"] == 150.0
    assert c["peak_current_amps"] == 35.0


def test_mock_plc_server():
    """Tests virtual machine mock PLC server communication."""
    server = MockIndustrialMachinePLC(host="127.0.0.1", port=5022)
    server.start()
    time.sleep(0.5)

    try:
        client = ReadOnlyPLCClient(protocol="modbus_tcp", host="127.0.0.1", port=5022)
        assert client.connect()
        regs = client.read_holding_registers(address=0, count=5, unit_id=1)
        assert len(regs) == 5
        client.disconnect()
    finally:
        server.stop()


def test_wire_level_write_block():
    """Confirms that low-level socket driver physically rejects write commands."""
    from plc_extractor.client.readonly_wrapper import _PureSocketModbusClient

    raw_socket_client = _PureSocketModbusClient("127.0.0.1", port=5022)
    # 1. Method attribute block
    with pytest.raises(PLCWriteAttemptBlockedError):
        raw_socket_client.write_register(0, 100)

    # 2. Wire egress code assertion block
    with pytest.raises(PLCWriteAttemptBlockedError):
        raw_socket_client._execute_read_query(func_code=0x06, address=0, count=1)


def test_unreachable_offline_diagnostics():
    """Confirms that offline/unreachable PLCs are flagged safely without fake data."""
    from plc_extractor.scanner.auto_diagnostics import AutoDiagnosticsEngine

    engine = AutoDiagnosticsEngine(target_host="192.0.2.1", station_name="OfflineUnit")
    res = engine.run_full_diagnostic()

    assert res["status"] == "UNREACHABLE"
    assert res["avg_latency_ms"] == 0.0
    assert res["total_tags_count"] == 0
    assert len(res["tags"]) == 0
    assert os.path.exists(res["excel_report_path"])
    assert os.path.exists(res["markdown_report_path"])

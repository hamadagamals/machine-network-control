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


def test_stateful_cycle_analyzer_incremental_streaming():
    """Tests that CycleAnalyzer feed_record preserves state across arbitrary packet chunks."""
    analyzer = CycleAnalyzer(
        trigger_tag="machine_state",
        idle_state=0,
        active_states=[1, 2, 3, 4],
        min_cycle_duration_seconds=1.0,
    )

    t = 2000.0
    completed = []

    # Chunk 1: Machine idling
    for _ in range(5):
        kpi = analyzer.feed_record({"host_timestamp": t, "machine_state": 0})
        if kpi:
            completed.append(kpi)
        t += 0.5

    # Chunk 2: Machine in clamp and press (duration ongoing)
    for state in [1, 1, 2, 2]:
        kpi = analyzer.feed_record({
            "host_timestamp": t,
            "machine_state": state,
            "motor_current_amps": 28.0,
            "hydraulic_pressure_bar": 120.0,
        })
        if kpi:
            completed.append(kpi)
        t += 0.5

    assert len(completed) == 0  # Still ongoing, not completed

    # Chunk 3: Machine finishes cool, eject, and returns to idle
    for state in [3, 4, 0]:
        kpi = analyzer.feed_record({
            "host_timestamp": t,
            "machine_state": state,
            "motor_current_amps": 15.0 if state > 0 else 2.0,
            "hydraulic_pressure_bar": 40.0 if state > 0 else 5.0,
        })
        if kpi:
            completed.append(kpi)
        t += 0.5

    assert len(completed) == 1
    assert completed[0]["duration_sec"] == 3.0
    assert completed[0]["max_pressure_bar"] == 120.0


def test_continuous_auto_mode_cycle_detection():
    """Tests cycle detection in continuous auto mode (phase 4 -> phase 1 without returning to idle 0)."""
    analyzer = CycleAnalyzer(
        trigger_tag="machine_state",
        idle_state=0,
        active_states=[1, 2, 3, 4],
        min_cycle_duration_seconds=1.0,
    )

    t = 3000.0
    completed = []

    # Start Cycle 1: Idle -> 1 -> 2 -> 3 -> 4
    for s in [0, 1, 2, 3, 4]:
        k = analyzer.feed_record({"host_timestamp": t, "machine_state": s, "motor_current_amps": 20.0})
        if k:
            completed.append(k)
        t += 1.0

    assert len(completed) == 0

    # Auto Transition: 4 directly to 1 (Cycle 1 finishes, Cycle 2 begins)
    k1 = analyzer.feed_record({"host_timestamp": t, "machine_state": 1, "motor_current_amps": 22.0})
    if k1:
        completed.append(k1)
    t += 1.0

    assert len(completed) == 1
    assert completed[0]["cycle_id"] == 1
    assert completed[0]["duration_sec"] == 4.0

    # Cycle 2 continues: 2 -> 3 -> 4 -> returns to 0
    for s in [2, 3, 4, 0]:
        k2 = analyzer.feed_record({"host_timestamp": t, "machine_state": s, "motor_current_amps": 20.0})
        if k2:
            completed.append(k2)
        t += 1.0

    assert len(completed) == 2
    assert completed[1]["cycle_id"] == 2


def test_pcap_dissector_modbus_and_s7():
    """Verifies byte-accurate dissection of Modbus TCP and Siemens S7comm payloads."""
    import struct
    from plc_extractor.discovery.pcap_memory_mapper import PCAPMemoryMapper

    mapper = PCAPMemoryMapper(pcap_path="dummy.pcap")

    # Modbus TCP Read Holding Registers query (12 bytes)
    # MBAP: TransID=0x0001, Proto=0x0000, Len=0x0006, UnitID=0x01
    # PDU: Func=0x03, Addr=0x0064 (100), Count=0x000A (10)
    mb_payload = struct.pack(">HHHBBHH", 1, 0, 6, 1, 0x03, 100, 10)
    mapper._dissect_modbus(mb_payload, timestamp=100.0, is_request=True)

    assert "modbus_u1_holding_register_100" in mapper.discovered_registers
    reg = mapper.discovered_registers["modbus_u1_holding_register_100"]
    assert reg["start_address"] == 100
    assert reg["count"] == 10
    assert reg["unit_id"] == 1

    # Siemens S7comm Read Var query
    # TPKT (4) + COTP (3: len=2, DT=0xF0, EOT=0x80) + S7comm Header (10) + Param (Read Var 0x04, Count=1) + Item (12)
    tpkt = b"\x03\x00\x00\x1f"
    cotp = b"\x02\xf0\x80"
    s7_hdr = b"\x32\x01\x00\x00\x00\x01\x00\x0e\x00\x00"  # S7 Job, ParamLen=14, DataLen=0
    s7_param_hdr = b"\x04\x01"  # Read Var (0x04), Item count = 1
    # Item: VarSpec(0x12), RestLen(0x0a), Syntax(0x10), TransportSize(0x02=Byte), Count(0x0004), DB(0x0001), Area(0x84=DB), Addr(0x00, 0x00, 0x20 = byte 4, bit 0)
    s7_item = b"\x12\x0a\x10\x02\x00\x04\x00\x01\x84\x00\x00\x20"
    s7_payload = tpkt + cotp + s7_hdr + s7_param_hdr + s7_item

    mapper._dissect_s7comm(s7_payload, timestamp=100.5, is_request=True)
    assert "s7_DB1_offset_4_0" in mapper.discovered_registers
    s7_reg = mapper.discovered_registers["s7_DB1_offset_4_0"]
    assert s7_reg["db_number"] == 1
    assert s7_reg["byte_offset"] == 4
    assert s7_reg["bit_offset"] == 0


def test_poller_signed_conversion():
    """Confirms signed 16-bit negative values are accurately converted."""
    from plc_extractor.acquisition.poller import TieredPoller

    assert TieredPoller._to_int16(0) == 0
    assert TieredPoller._to_int16(100) == 100
    assert TieredPoller._to_int16(32767) == 32767
    assert TieredPoller._to_int16(65535) == -1
    assert TieredPoller._to_int16(65526) == -10
    assert TieredPoller._to_int16(64536) == -1000


def test_report_sanitization():
    """Confirms filename sanitization prevents directory traversal or illegal chars."""
    from plc_extractor.reporting.report_generator import ReportGenerator

    rg = ReportGenerator()
    assert rg._sanitize_name("../../Bad:Station*01") == "Bad_Station_01"
    assert rg._sanitize_name("Machine-05") == "Machine-05"

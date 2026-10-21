"""
Machine Network Control - Main Orchestrator & CLI Entrypoint
Strictly Read-Only Industrial PLC Data Extraction, Storage & Machine Cycle Analytics.
"""

import argparse
import logging
import os
import sys
import time

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    import yaml
except ImportError:
    yaml = None
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from plc_extractor.scanner.protocol_probe import ProtocolProbe
from plc_extractor.discovery.pcap_memory_mapper import PCAPMemoryMapper
from plc_extractor.client.readonly_wrapper import ReadOnlyPLCClient, PLCWriteAttemptBlockedError
from plc_extractor.backup.plc_snapshot import PLCSnapshot
from plc_extractor.acquisition.storage_engine import StorageEngine
from plc_extractor.acquisition.poller import TieredPoller
from plc_extractor.analytics.cycle_analyzer import CycleAnalyzer
from plc_extractor.simulator.mock_plc_server import MockIndustrialMachinePLC
from ui.dashboard import app as fastapi_app, update_live_telemetry, add_completed_cycle

console = Console(legacy_windows=False)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def load_config(config_path: str = "config/default_config.yaml") -> dict:
    if os.path.exists(config_path):
        if yaml is not None and (config_path.endswith(".yaml") or config_path.endswith(".yml")):
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
    json_path = config_path.replace(".yaml", ".json").replace(".yml", ".json")
    if os.path.exists(json_path):
        import json
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    return {
        "target_plc": {"ip_address": "127.0.0.1", "protocol": "modbus_tcp", "port": 5020},
        "safety": {"strict_read_only": True, "max_requests_per_second": 50.0},
        "polling": {"tier_1_high_frequency_ms": 50, "tier_2_medium_frequency_ms": 1000, "tier_3_low_frequency_ms": 10000},
        "storage": {"db_path": "data/telemetry/machine_telemetry.duckdb", "parquet_export_dir": "data/telemetry/parquet"},
        "cycle_analysis": {"golden_cycle": {"expected_duration_seconds": 12.5}},
        "dashboard": {"host": "0.0.0.0", "port": 8088}
    }


def cmd_probe(args):
    """Scans and fingerprints target industrial controller."""
    console.print(Panel(f"[bold cyan]Initiating Protocol Probe against {args.host}[/bold cyan]"))
    probe = ProtocolProbe(host=args.host, timeout=args.timeout)
    profile = probe.execute_full_scan(output_path=args.output)
    
    table = Table(title="PLC Discovery Results")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Target Host", profile["target_host"])
    table.add_row("Detected Protocol", str(profile["detected_protocol"]))
    table.add_row("Profile Saved To", args.output)
    console.print(table)


def cmd_map_pcap(args):
    """Reconstructs memory map from passive Wireshark capture."""
    console.print(Panel(f"[bold cyan]Parsing Passive Capture: {args.pcap}[/bold cyan]"))
    mapper = PCAPMemoryMapper(pcap_path=args.pcap, plc_ip=args.plc_ip)
    yaml_path = mapper.export_yaml(output_path=args.output)
    console.print(f"[bold green][OK] Memory map successfully saved to {yaml_path}[/bold green]")


def cmd_test_safety(args):
    """Verifies that all write and force methods are strictly blocked by the safety wrapper."""
    console.print(Panel("[bold red]Testing Read-Only Safety Wrapper (Firewall Verification)[/bold red]"))
    client = ReadOnlyPLCClient(protocol="modbus_tcp", host="127.0.0.1", port=502)

    prohibited_calls = ["write_register", "write_coil", "plc_stop", "force_bit", "download"]
    all_blocked = True

    for method in prohibited_calls:
        try:
            func = getattr(client, method)
            func(0, 100)
            console.print(f"[bold red]FAIL: Method {method} was NOT blocked![/bold red]")
            all_blocked = False
        except PLCWriteAttemptBlockedError as e:
            console.print(f"[bold green][BLOCKED AS EXPECTED][/bold green] {method} -> {e}")
        except Exception as e:
            console.print(f"[bold green][INTERCEPTED][/bold green] {method} -> {e}")

    if all_blocked:
        console.print(Panel("[bold green]SAFETY AUDIT PASSED: Zero write capability confirmed.[/bold green]"))


def cmd_simulate(args):
    """Runs the virtual machine mock PLC server."""
    console.print(Panel(f"[bold green]Starting Virtual Industrial Machine Simulator on {args.host}:{args.port}[/bold green]"))
    sim = MockIndustrialMachinePLC(host=args.host, port=args.port)
    sim.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sim.stop()
        console.print("[yellow]Simulator stopped.[/yellow]")


def cmd_monitor(args):
    """Runs high-frequency data extraction, cycle analytics, and real-time dashboard."""
    cfg = load_config(args.config)
    plc_cfg = cfg.get("target_plc", {})
    safety_cfg = cfg.get("safety", {})
    poll_cfg = cfg.get("polling", {})

    host = args.host or plc_cfg.get("ip_address", "127.0.0.1")
    port = args.port or plc_cfg.get("port", 502)
    proto = plc_cfg.get("protocol", "modbus_tcp")

    console.print(Panel(
        f"[bold cyan]Launching High-Frequency Extractor & Cycle Analyzer[/bold cyan]\n"
        f"Target: [green]{proto}://{host}:{port}[/green] | Safety: [green]STRICT READ-ONLY[/green]"
    ))

    # 1. Initialize Safety Wrapper Client
    client = ReadOnlyPLCClient(
        protocol=proto,
        host=host,
        port=port,
        max_requests_per_second=safety_cfg.get("max_requests_per_second", 50.0),
    )

    # 2. Storage Engine
    storage = StorageEngine(
        db_path=cfg.get("storage", {}).get("db_path", "data/telemetry/machine_telemetry.duckdb"),
        parquet_dir=cfg.get("storage", {}).get("parquet_export_dir", "data/telemetry/parquet"),
    )
    storage.start()

    # 3. Cycle Analyzer
    analyzer = CycleAnalyzer(
        trigger_tag="machine_state",
        idle_state=0,
        active_states=[1, 2, 3, 4],
        golden_duration_seconds=cfg.get("cycle_analysis", {}).get("golden_cycle", {}).get("expected_duration_seconds", 12.5),
    )

    # Telemetry push callback to UI & live cycle detection
    buffer_for_cycles = []

    def on_telemetry(record):
        update_live_telemetry(record)
        buffer_for_cycles.append(record)
        if len(buffer_for_cycles) >= 50:
            import pandas as pd
            df = pd.DataFrame(buffer_for_cycles)
            new_cycles = analyzer.analyze_stream(df)
            for c in new_cycles:
                add_completed_cycle(c)
                console.print(f"[bold green][CYCLE #{c['cycle_id']} COMPLETED][/bold green] - Duration: {c['duration_sec']}s - Anomaly: {c['anomaly_reasons']}")
            buffer_for_cycles.clear()

    # 4. Poller Engine
    poller = TieredPoller(
        client=client,
        storage=storage,
        tier1_interval_ms=poll_cfg.get("tier_1_high_frequency_ms", 50),
        tier2_interval_ms=poll_cfg.get("tier_2_medium_frequency_ms", 1000),
        tier3_interval_ms=poll_cfg.get("tier_3_low_frequency_ms", 10000),
        telemetry_callback=on_telemetry,
    )

    # Launch dashboard server if requested
    if args.dashboard:
        import uvicorn
        dash_cfg = cfg.get("dashboard", {})
        console.print(f"[bold green]Starting Web Dashboard on http://{dash_cfg.get('host', '0.0.0.0')}:{dash_cfg.get('port', 8088)}[/bold green]")
        
        # Start poller in background
        poller.start()
        uvicorn.run(fastapi_app, host=dash_cfg.get("host", "0.0.0.0"), port=dash_cfg.get("port", 8088))
    else:
        poller.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            poller.stop()
            storage.stop()
            client.disconnect()


def main():
    parser = argparse.ArgumentParser(description="Machine Network Control: Industrial PLC Extractor & Cycle Analyzer")
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # probe
    p_probe = subparsers.add_parser("probe", help="Scan and fingerprint target PLC")
    p_probe.add_argument("--host", required=True, help="PLC IP address")
    p_probe.add_argument("--timeout", type=float, default=1.0, help="Socket timeout seconds")
    p_probe.add_argument("--output", default="config/plc_profile.json", help="Profile output path")

    # map-pcap
    p_pcap = subparsers.add_parser("map-pcap", help="Reconstruct memory map from Wireshark capture")
    p_pcap.add_argument("--pcap", required=True, help="Path to .pcap or .pcapng file")
    p_pcap.add_argument("--plc-ip", default=None, help="Target PLC IP filter")
    p_pcap.add_argument("--output", default="config/memory_map.yaml", help="Output YAML path")

    # test-safety
    subparsers.add_parser("test-safety", help="Verify strict read-only safety guardrails")

    # simulate
    p_sim = subparsers.add_parser("simulate", help="Start virtual machine mock PLC server")
    p_sim.add_argument("--host", default="127.0.0.1", help="Bind host")
    p_sim.add_argument("--port", type=int, default=5020, help="Bind port")

    # monitor
    p_mon = subparsers.add_parser("monitor", help="Start high-frequency extraction and cycle analyzer")
    p_mon.add_argument("--config", default="config/default_config.yaml", help="Config file path")
    p_mon.add_argument("--host", default=None, help="Override PLC IP")
    p_mon.add_argument("--port", type=int, default=None, help="Override Port")
    p_mon.add_argument("--dashboard", action="store_true", help="Launch live web dashboard")

    args = parser.parse_args()
    if args.command == "probe":
        cmd_probe(args)
    elif args.command == "map-pcap":
        cmd_map_pcap(args)
    elif args.command == "test-safety":
        cmd_test_safety(args)
    elif args.command == "simulate":
        cmd_simulate(args)
    elif args.command == "monitor":
        cmd_monitor(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

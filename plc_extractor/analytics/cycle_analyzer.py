"""
Automated Machine Cycle Analysis & Anomaly Detection
Segments continuous high-frequency telemetry into discrete production cycles,
calculates phase timings, extracts analog signatures, and flags mechanical anomalies.
"""

import logging
import time
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd

logger = logging.getLogger("CycleAnalyzer")


class CycleAnalyzer:
    """
    Forensic cycle segmentation and feature extraction engine.
    """

    def __init__(
        self,
        trigger_tag: str = "machine_state",
        idle_state: int = 0,
        active_states: Optional[List[int]] = None,
        min_cycle_duration_seconds: float = 1.0,
        debounce_ms: float = 100.0,
        golden_duration_seconds: float = 12.5,
        duration_tolerance_percent: float = 15.0,
    ):
        self.trigger_tag = trigger_tag
        self.idle_state = idle_state
        self.active_states = active_states or [1, 2, 3, 4]
        self.min_duration = min_cycle_duration_seconds
        self.debounce_sec = debounce_ms / 1000.0
        self.golden_duration = golden_duration_seconds
        self.tolerance_pct = duration_tolerance_percent

        self.current_cycle_id = 0
        self.completed_cycles: List[Dict[str, Any]] = []

    def analyze_stream(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Analyzes a continuous DataFrame of telemetry and returns segmented cycle KPIs."""
        if df.empty or self.trigger_tag not in df.columns:
            return []

        df = df.sort_values("host_timestamp").reset_index(drop=True)
        cycles = []

        in_cycle = False
        cycle_start_time = None
        cycle_start_idx = None
        last_state = self.idle_state

        for idx, row in df.iterrows():
            curr_state = int(row.get(self.trigger_tag, self.idle_state))
            t = float(row["host_timestamp"])

            # Transition from Idle to Active -> Cycle Start
            if not in_cycle and curr_state in self.active_states and last_state == self.idle_state:
                in_cycle = True
                cycle_start_time = t
                cycle_start_idx = idx

            # Transition from Active to Idle -> Cycle End
            elif in_cycle and curr_state == self.idle_state:
                cycle_end_time = t
                duration = cycle_end_time - cycle_start_time

                if duration >= self.min_duration:
                    cycle_df = df.iloc[cycle_start_idx:idx]
                    kpi = self._compute_cycle_kpi(cycle_df, cycle_start_time, cycle_end_time, duration)
                    cycles.append(kpi)

                in_cycle = False
                cycle_start_time = None
                cycle_start_idx = None

            last_state = curr_state

        self.completed_cycles.extend(cycles)
        return cycles

    def _compute_cycle_kpi(
        self, cycle_df: pd.DataFrame, t_start: float, t_end: float, duration: float
    ) -> Dict[str, Any]:
        """Calculates engineering features and anomaly flags for a single completed cycle."""
        self.current_cycle_id += 1

        # Phase breakdowns
        phase_counts = cycle_df[self.trigger_tag].value_counts().to_dict()
        dt = duration / max(1, len(cycle_df))
        phases_timing = {f"phase_{k}_sec": round(v * dt, 2) for k, v in phase_counts.items()}

        # Analog signatures
        peak_current = float(cycle_df["motor_current_amps"].max()) if "motor_current_amps" in cycle_df else 0.0
        mean_current = float(cycle_df["motor_current_amps"].mean()) if "motor_current_amps" in cycle_df else 0.0
        max_pressure = float(cycle_df["hydraulic_pressure_bar"].max()) if "hydraulic_pressure_bar" in cycle_df else 0.0
        mean_temp = float(cycle_df["oil_temperature_c"].mean()) if "oil_temperature_c" in cycle_df else 0.0

        # Integral energy (approximated proxy: sum(I * dt))
        energy_integral = float((cycle_df["motor_current_amps"] * dt).sum()) if "motor_current_amps" in cycle_df else 0.0

        # Anomaly Detection vs Golden Baseline
        anomaly_flags = []
        dur_diff_pct = abs(duration - self.golden_duration) / self.golden_duration * 100.0
        if dur_diff_pct > self.tolerance_pct:
            anomaly_flags.append(f"CYCLE_TIME_DRIFT ({dur_diff_pct:.1f}% deviation)")

        if peak_current > 45.0:
            anomaly_flags.append("HIGH_PEAK_MOTOR_CURRENT")

        if max_pressure > 180.0:
            anomaly_flags.append("HYDRAULIC_OVERPRESSURE")

        kpi_record = {
            "cycle_id": self.current_cycle_id,
            "start_time": time.strftime("%H:%M:%S", time.localtime(t_start)),
            "end_time": time.strftime("%H:%M:%S", time.localtime(t_end)),
            "duration_sec": round(duration, 3),
            "peak_current_amps": round(peak_current, 2),
            "mean_current_amps": round(mean_current, 2),
            "max_pressure_bar": round(max_pressure, 2),
            "mean_temp_c": round(mean_temp, 1),
            "energy_integral": round(energy_integral, 2),
            "anomaly_detected": len(anomaly_flags) > 0,
            "anomaly_reasons": ", ".join(anomaly_flags) if anomaly_flags else "NORMAL",
            "phase_timings": phases_timing,
        }

        return kpi_record

    def get_summary_dataframe(self) -> pd.DataFrame:
        """Returns completed cycles as a clean summary DataFrame."""
        return pd.DataFrame(self.completed_cycles)

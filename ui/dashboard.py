"""
Industrial Edge Real-Time Telemetry & Cycle Analysis Dashboard
FastAPI + WebSockets streaming with dark industrial aesthetics.
"""

import asyncio
import json
import os
from typing import Any, Dict, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

app = FastAPI(title="Industrial PLC Extraction & Cycle Monitor")

# In-memory streaming state
connected_websockets: List[WebSocket] = []
latest_telemetry: Dict[str, Any] = {
    "machine_state": 0,
    "hydraulic_pressure_bar": 0.0,
    "motor_current_amps": 0.0,
    "oil_temperature_c": 0.0,
    "shift_part_counter": 0,
    "latency_ms": 0.0,
    "safety_lock": "ACTIVE_READ_ONLY",
}
recent_cycles: List[Dict[str, Any]] = []


def update_live_telemetry(record: Dict[str, Any]):
    """Called by poller thread to push new data to dashboard."""
    global latest_telemetry
    latest_telemetry.update(record)


def add_completed_cycle(cycle_kpi: Dict[str, Any]):
    """Called by cycle analyzer when a new machine cycle finishes."""
    global recent_cycles
    recent_cycles.insert(0, cycle_kpi)
    if len(recent_cycles) > 20:
        recent_cycles.pop()


HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Machine Network Control | Industrial Edge Monitor</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-base: #0B0F19;
            --bg-card: #131B2E;
            --bg-card-hover: #1A243D;
            --border-color: #1F2E4D;
            --text-main: #E2E8F0;
            --text-muted: #94A3B8;
            --accent-cyan: #06B6D4;
            --accent-blue: #3B82F6;
            --accent-green: #10B981;
            --accent-amber: #F59E0B;
            --accent-red: #EF4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            padding: 24px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 24px;
        }
        .title-group h1 { font-size: 24px; font-weight: 700; color: #FFF; }
        .title-group p { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
        .safety-badge {
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid var(--accent-green);
            color: var(--accent-green);
            padding: 8px 16px;
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: 'JetBrains Mono', monospace;
        }
        .pulse-dot {
            width: 8px; height: 8px;
            border-radius: 50%;
            background: var(--accent-green);
            box-shadow: 0 0 10px var(--accent-green);
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            transition: all 0.2s ease;
        }
        .card:hover { border-color: var(--accent-cyan); background: var(--bg-card-hover); }
        .card-title { font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
        .card-value {
            font-size: 28px;
            font-weight: 700;
            margin-top: 10px;
            font-family: 'JetBrains Mono', monospace;
            color: #FFF;
        }
        .card-unit { font-size: 14px; color: var(--text-muted); font-weight: 400; margin-left: 4px; }

        .main-layout {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 24px;
        }
        .chart-container {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            height: 380px;
        }
        .table-container {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 12px;
        }
        th, td {
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
        }
        th { color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 11px; }
        td { font-family: 'JetBrains Mono', monospace; }
        .status-pill {
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
        }
        .pill-normal { background: rgba(16, 185, 129, 0.15); color: var(--accent-green); }
        .pill-anomaly { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); }
    </style>
</head>
<body>
    <div class="header">
        <div class="title-group">
            <h1>Machine Network Control | Industrial Edge Monitor</h1>
            <p>Station: Machine-01 | Frequency: 20 Hz (50ms) | Zero-Plant-Impact Protocol</p>
        </div>
        <div class="safety-badge">
            <span class="pulse-dot"></span>
            HARDWARE SAFETY LOCK: STRICT READ-ONLY
        </div>
    </div>

    <div class="kpi-grid">
        <div class="card">
            <div class="card-title">Machine State</div>
            <div class="card-value" id="val-state" style="color: var(--accent-cyan);">IDLE (0)</div>
        </div>
        <div class="card">
            <div class="card-title">Hydraulic Pressure</div>
            <div class="card-value"><span id="val-pressure">0.0</span><span class="card-unit">Bar</span></div>
        </div>
        <div class="card">
            <div class="card-title">Motor Current</div>
            <div class="card-value"><span id="val-current">0.0</span><span class="card-unit">Amps</span></div>
        </div>
        <div class="card">
            <div class="card-title">Oil Temperature</div>
            <div class="card-value"><span id="val-temp">0.0</span><span class="card-unit">°C</span></div>
        </div>
        <div class="card">
            <div class="card-title">Cycle Counter</div>
            <div class="card-value" id="val-counter" style="color: var(--accent-green);">0</div>
        </div>
        <div class="card">
            <div class="card-title">Polling Latency</div>
            <div class="card-value"><span id="val-latency">0.0</span><span class="card-unit">ms</span></div>
        </div>
    </div>

    <div class="main-layout">
        <div class="chart-container">
            <h3 style="font-size: 15px; margin-bottom: 15px;">Live High-Frequency Telemetry Stream</h3>
            <canvas id="telemetryChart"></canvas>
        </div>
        <div class="table-container">
            <h3 style="font-size: 15px;">Recent Machine Cycles (Cycle Analytics)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Cycle #</th>
                        <th>Duration</th>
                        <th>Peak Current</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="cycleTableBody">
                    <tr><td colspan="4" style="color: var(--text-muted); text-align: center;">Awaiting cycle completion...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const states = { 0: "IDLE", 1: "CLAMPING", 2: "PRESSING", 3: "COOLING", 4: "EJECTING" };
        
        // Chart setup
        const ctx = document.getElementById('telemetryChart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: Array(30).fill(''),
                datasets: [
                    { label: 'Pressure (Bar)', borderColor: '#06B6D4', data: Array(30).fill(0), borderWidth: 2, pointRadius: 0, tension: 0.3 },
                    { label: 'Current (Amps)', borderColor: '#F59E0B', data: Array(30).fill(0), borderWidth: 2, pointRadius: 0, tension: 0.3 }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { display: false },
                    y: { grid: { color: '#1F2E4D' }, ticks: { color: '#94A3B8' } }
                },
                plugins: { legend: { labels: { color: '#E2E8F0' } } }
            }
        });

        // WebSocket connection
        const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${wsProto}//${window.location.host}/ws`);

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.telemetry) {
                const t = data.telemetry;
                const stateText = states[t.machine_state] || `STATE ${t.machine_state}`;
                document.getElementById('val-state').innerText = `${stateText} (${t.machine_state})`;
                document.getElementById('val-pressure').innerText = t.hydraulic_pressure_bar ? t.hydraulic_pressure_bar.toFixed(1) : '0.0';
                document.getElementById('val-current').innerText = t.motor_current_amps ? t.motor_current_amps.toFixed(1) : '0.0';
                document.getElementById('val-temp').innerText = t.oil_temperature_c ? t.oil_temperature_c.toFixed(1) : '0.0';
                document.getElementById('val-counter').innerText = t.shift_part_counter || '0';
                document.getElementById('val-latency').innerText = t.latency_ms ? t.latency_ms.toFixed(1) : '0.0';

                // Update chart
                chart.data.datasets[0].data.push(t.hydraulic_pressure_bar || 0);
                chart.data.datasets[0].data.shift();
                chart.data.datasets[1].data.push(t.motor_current_amps || 0);
                chart.data.datasets[1].data.shift();
                chart.update('none');
            }

            if (data.cycles && data.cycles.length > 0) {
                const tbody = document.getElementById('cycleTableBody');
                tbody.innerHTML = data.cycles.slice(0, 8).map(c => `
                    <tr>
                        <td>#${c.cycle_id}</td>
                        <td>${c.duration_sec}s</td>
                        <td>${c.peak_current_amps}A</td>
                        <td><span class="status-pill ${c.anomaly_detected ? 'pill-anomaly' : 'pill-normal'}">${c.anomaly_reasons}</span></td>
                    </tr>
                `).join('');
            }
        };
    </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    return HTML_CONTENT


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        while True:
            payload = {
                "telemetry": latest_telemetry,
                "cycles": recent_cycles,
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(0.1)  # 10 Hz update
    except WebSocketDisconnect:
        connected_websockets.remove(websocket)

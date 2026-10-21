"""
Industrial Edge Real-Time Telemetry & Automated Diagnostic Web Portal
FastAPI + WebSockets + 1-Click Interactive Wizard + Multi-Format Report Downloads.
"""

import asyncio
import json
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from plc_extractor.scanner.auto_diagnostics import AutoDiagnosticsEngine
from plc_extractor.simulator.mock_plc_server import MockIndustrialMachinePLC
from plc_extractor.client.readonly_wrapper import ReadOnlyPLCClient
from plc_extractor.acquisition.storage_engine import StorageEngine
from plc_extractor.acquisition.poller import TieredPoller
from plc_extractor.analytics.cycle_analyzer import CycleAnalyzer

logger = logging.getLogger("Dashboard")
app = FastAPI(title="Machine Network Control - Automated Industrial Portal")

# Global System State
diagnostic_state: Dict[str, Any] = {
    "is_running": False,
    "progress_percent": 0,
    "current_step": "جاهز لبدء الفحص الآلي للماكينة",
    "result": None,
    "user_answers": {},
}

live_telemetry: Dict[str, Any] = {
    "machine_state": 0,
    "hydraulic_pressure_bar": 0.0,
    "motor_current_amps": 0.0,
    "oil_temperature_c": 0.0,
    "shift_part_counter": 0,
    "latency_ms": 0.0,
    "safety_lock": "STRICT_READ_ONLY",
}
completed_cycles: List[Dict[str, Any]] = []
connected_websockets: List[WebSocket] = []

# Background Services
mock_plc_instance: Optional[MockIndustrialMachinePLC] = None
poller_instance: Optional[TieredPoller] = None
storage_instance: Optional[StorageEngine] = None
analyzer_instance: Optional[CycleAnalyzer] = None


class AuditRequest(BaseModel):
    ip_address: str = "127.0.0.1"
    station_name: str = "Machine-01"


class AnswerSubmission(BaseModel):
    answers: Dict[str, str]


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML_CONTENT


# ------------------------------------------------------------------------------
# API ENDPOINTS FOR 1-CLICK AUTOMATION
# ------------------------------------------------------------------------------
@app.post("/api/audit/start")
def start_audit(req: AuditRequest):
    global diagnostic_state
    if diagnostic_state["is_running"]:
        return {"status": "ALREADY_RUNNING"}

    diagnostic_state["is_running"] = True
    diagnostic_state["progress_percent"] = 5
    diagnostic_state["current_step"] = "بدء الفحص الآلي المتسلسل..."
    diagnostic_state["result"] = None

    def _run():
        engine = AutoDiagnosticsEngine(target_host=req.ip_address, station_name=req.station_name)
        def _cb(percent, msg, partial):
            diagnostic_state["progress_percent"] = percent
            diagnostic_state["current_step"] = msg
            if partial:
                diagnostic_state["result"] = partial

        engine.set_callback(_cb)
        res = engine.run_full_diagnostic()
        diagnostic_state["is_running"] = False
        diagnostic_state["result"] = res

    threading.Thread(target=_run, daemon=True).start()
    return {"status": "STARTED"}


@app.get("/api/audit/status")
def get_audit_status():
    return diagnostic_state


@app.post("/api/audit/answer")
def submit_answers(sub: AnswerSubmission):
    global diagnostic_state
    diagnostic_state["user_answers"].update(sub.answers)
    # If a result exists, re-generate reports with user answers
    if diagnostic_state.get("result"):
        res = diagnostic_state["result"]
        res["user_answers"] = diagnostic_state["user_answers"]
        from plc_extractor.reporting.report_generator import ReportGenerator
        rg = ReportGenerator()
        res["excel_report_path"] = rg.generate_excel_report(res)
        res["markdown_report_path"] = rg.generate_markdown_report(res)
    return {"status": "UPDATED", "answers": diagnostic_state["user_answers"]}


@app.get("/api/reports/download/excel")
def download_excel():
    res = diagnostic_state.get("result")
    if res and res.get("excel_report_path") and os.path.exists(res["excel_report_path"]):
        return FileResponse(
            res["excel_report_path"],
            filename=os.path.basename(res["excel_report_path"]),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    raise HTTPException(status_code=404, detail="No Excel report available yet. Run audit first.")


@app.get("/api/reports/download/markdown")
def download_markdown():
    res = diagnostic_state.get("result")
    if res and res.get("markdown_report_path") and os.path.exists(res["markdown_report_path"]):
        return FileResponse(
            res["markdown_report_path"],
            filename=os.path.basename(res["markdown_report_path"]),
            media_type="text/markdown",
        )
    raise HTTPException(status_code=404, detail="No Markdown report available yet. Run audit first.")


@app.post("/api/simulator/toggle")
def toggle_simulator(port: int = 5020):
    global mock_plc_instance
    if mock_plc_instance is None:
        mock_plc_instance = MockIndustrialMachinePLC(host="127.0.0.1", port=port)
        mock_plc_instance.start()
        return {"status": "RUNNING", "port": port}
    else:
        mock_plc_instance.stop()
        mock_plc_instance = None
        return {"status": "STOPPED"}


@app.post("/api/monitor/toggle")
def toggle_monitor(host: str = "127.0.0.1", port: int = 5020):
    global poller_instance, storage_instance, analyzer_instance
    if poller_instance is None:
        client = ReadOnlyPLCClient(protocol="modbus_tcp", host=host, port=port)
        storage_instance = StorageEngine()
        storage_instance.start()

        analyzer_instance = CycleAnalyzer()
        cycle_buf = []

        def _on_telem(rec):
            live_telemetry.update(rec)
            cycle_buf.append(rec)
            if len(cycle_buf) >= 40:
                import pandas as pd
                new_c = analyzer_instance.analyze_stream(pd.DataFrame(cycle_buf))
                for c in new_c:
                    completed_cycles.insert(0, c)
                    if len(completed_cycles) > 20:
                        completed_cycles.pop()
                cycle_buf.clear()

        poller_instance = TieredPoller(
            client=client,
            storage=storage_instance,
            tier1_interval_ms=50,
            telemetry_callback=_on_telem,
        )
        poller_instance.start()
        return {"status": "MONITORING_ACTIVE"}
    else:
        poller_instance.stop()
        poller_instance = None
        if storage_instance:
            storage_instance.stop()
            storage_instance = None
        return {"status": "MONITORING_STOPPED"}


@app.websocket("/ws")
async def websocket_stream(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        while True:
            payload = {
                "telemetry": live_telemetry,
                "cycles": completed_cycles[:8],
                "audit": diagnostic_state,
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(0.1)  # 10 Hz
    except WebSocketDisconnect:
        connected_websockets.remove(websocket)


# ------------------------------------------------------------------------------
# FRONTEND USER INTERFACE (HTML + CSS + JAVASCRIPT)
# ------------------------------------------------------------------------------
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Machine Network Control | نظام الربط الآلي وتدقيق الماكينات</title>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-base: #0B0F19;
            --bg-card: #131B2E;
            --bg-card-hover: #1A243D;
            --border-color: #1F2E4D;
            --text-main: #F1F5F9;
            --text-muted: #94A3B8;
            --accent-cyan: #06B6D4;
            --accent-blue: #3B82F6;
            --accent-green: #10B981;
            --accent-amber: #F59E0B;
            --accent-red: #EF4444;
            --btn-gradient: linear-gradient(135deg, #06B6D4 0%, #3B82F6 100%);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Cairo', sans-serif;
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
            flex-wrap: wrap;
            gap: 16px;
        }
        .title-group h1 { font-size: 22px; font-weight: 800; color: #FFF; }
        .title-group p { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
        .safety-badge {
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid var(--accent-green);
            color: var(--accent-green);
            padding: 8px 18px;
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .pulse-dot {
            width: 10px; height: 10px;
            border-radius: 50%;
            background: var(--accent-green);
            box-shadow: 0 0 12px var(--accent-green);
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

        /* Action Control Bar */
        .control-bar {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 16px;
        }
        .input-group {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .input-group label { font-size: 13px; font-weight: 600; color: var(--text-muted); }
        .input-field {
            background: #0B0F19;
            border: 1px solid var(--border-color);
            color: #FFF;
            padding: 10px 14px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            outline: none;
        }
        .input-field:focus { border-color: var(--accent-cyan); }
        .btn-group { display: flex; gap: 12px; flex-wrap: wrap; }
        .btn {
            padding: 11px 22px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            border: none;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: 'Cairo', sans-serif;
        }
        .btn-primary {
            background: var(--btn-gradient);
            color: #FFF;
            box-shadow: 0 4px 14px rgba(6, 182, 212, 0.3);
        }
        .btn-primary:hover { opacity: 0.95; transform: translateY(-1px); }
        .btn-secondary {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid var(--border-color);
            color: #FFF;
        }
        .btn-secondary:hover { background: rgba(255, 255, 255, 0.12); }
        .btn-success {
            background: rgba(16, 185, 129, 0.2);
            border: 1px solid var(--accent-green);
            color: var(--accent-green);
        }
        .btn-success:hover { background: rgba(16, 185, 129, 0.3); }

        /* Wizard & Automated Diagnosis Section */
        .wizard-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 24px;
            margin-bottom: 24px;
        }
        .wizard-title { font-size: 16px; font-weight: 700; margin-bottom: 12px; }
        .progress-bar-container {
            width: 100%;
            height: 10px;
            background: #0B0F19;
            border-radius: 6px;
            overflow: hidden;
            margin-bottom: 12px;
            border: 1px solid var(--border-color);
        }
        .progress-fill {
            height: 100%;
            background: var(--btn-gradient);
            width: 0%;
            transition: width 0.4s ease;
        }
        .step-text { font-size: 14px; color: var(--accent-cyan); font-weight: 600; }

        /* Report Ready & Download Actions */
        .report-box {
            margin-top: 20px;
            padding: 18px;
            background: rgba(6, 182, 212, 0.05);
            border: 1px solid var(--accent-cyan);
            border-radius: 10px;
            display: none;
        }
        .report-box.active { display: block; animation: fadeIn 0.3s ease; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

        /* Questions Box */
        .questions-box {
            margin-top: 16px;
            padding: 16px;
            background: rgba(245, 158, 11, 0.08);
            border: 1px solid var(--accent-amber);
            border-radius: 10px;
        }
        .q-item { margin-bottom: 12px; }
        .q-item label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; }

        /* KPI Dashboard Grid */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }
        .card-title { font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 700; }
        .card-value {
            font-size: 26px;
            font-weight: 800;
            margin-top: 10px;
            font-family: 'JetBrains Mono', monospace;
            color: #FFF;
        }
        .card-unit { font-size: 13px; color: var(--text-muted); font-weight: 400; margin-right: 4px; }

        .main-layout {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 24px;
        }
        @media (max-width: 900px) { .main-layout { grid-template-columns: 1fr; } }
        .chart-container, .table-container {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }
        .chart-container { height: 360px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 12px; }
        th, td { text-align: right; padding: 10px 12px; border-bottom: 1px solid var(--border-color); }
        th { color: var(--text-muted); font-weight: 700; font-size: 11px; text-transform: uppercase; }
        td { font-family: 'JetBrains Mono', monospace; }
        .status-pill { padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; }
        .pill-normal { background: rgba(16, 185, 129, 0.15); color: var(--accent-green); }
        .pill-anomaly { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); }
    </style>
</head>
<body>
    <div class="header">
        <div class="title-group">
            <h1>Machine Network Control | نظام الربط الآلي وتدقيق الماكينات</h1>
            <p>منصة سحب البيانات الفائقة وتحليل دورات الماكينة بدون تدخل يدوي | كود الماكينة محمي 100%</p>
        </div>
        <div class="safety-badge">
            <span class="pulse-dot"></span>
            جدار الحماية مفعل: قراءة فقط صارمة (Zero Plant Impact)
        </div>
    </div>

    <!-- 1-Click Action Control Bar -->
    <div class="control-bar">
        <div class="input-group">
            <label for="plc-ip">عنوان الـ PLC:</label>
            <input type="text" id="plc-ip" class="input-field" value="127.0.0.1" style="width: 140px;">
            <label for="station-name">اسم الماكينة:</label>
            <input type="text" id="station-name" class="input-field" value="Machine-01" style="width: 130px;">
        </div>
        <div class="btn-group">
            <button class="btn btn-primary" onclick="startAutoAudit()">
                <span>🚀</span> بدء الفحص الآلي الشامل للماكينة
            </button>
            <button class="btn btn-success" id="btn-monitor" onclick="toggleMonitor()">
                <span>⚡</span> بدء المراقبة الحية
            </button>
            <button class="btn btn-secondary" id="btn-sim" onclick="toggleSimulator()">
                <span>🤖</span> تشغيل ماكينة افتراضية للتجربة
            </button>
        </div>
    </div>

    <!-- Wizard & Automated Diagnosis Status -->
    <div class="wizard-card">
        <div class="wizard-title">حالة الفحص والتدقيق الآلي المتسلسل (Automated Diagnostic Wizard)</div>
        <div class="progress-bar-container">
            <div class="progress-fill" id="progressFill"></div>
        </div>
        <div class="step-text" id="stepText">جاهز لبدء الفحص الآلي للماكينة. اضغط زر [بدء الفحص الآلي الشامل] أعلاه.</div>

        <!-- Report Download Box (Appears when completed) -->
        <div class="report-box" id="reportBox">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
                <div>
                    <h3 style="color: var(--accent-cyan); font-size: 16px;">✓ تم اكتمال الفحص وتوليد التقرير الهندسي الشامل</h3>
                    <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">تم فحص المعالج وتحديد العناوين وسرعة الاستجابة بدقة. قم بتحميل التقرير فوراً:</p>
                </div>
                <div style="display: flex; gap: 10px;">
                    <a href="/api/reports/download/excel" class="btn btn-primary" download>
                        <span>📥</span> تحميل تقرير Excel مفصل (.xlsx)
                    </a>
                    <a href="/api/reports/download/markdown" class="btn btn-secondary" download>
                        <span>📄</span> تحميل تقرير Text / Markdown (.md)
                    </a>
                </div>
            </div>

            <!-- Smart Questions Box (if any info needs confirmation) -->
            <div class="questions-box" id="questionsBox" style="display: none;">
                <h4 style="color: var(--accent-amber); font-size: 14px; margin-bottom: 10px;">ℹ️ أسئلة سريعة لاستكمال التقرير (اختياري):</h4>
                <div id="questionsContainer"></div>
                <button class="btn btn-secondary" onclick="saveAnswers()" style="margin-top: 10px;">حفظ الإجابات وتحديث التقرير</button>
            </div>
        </div>
    </div>

    <!-- Live Telemetry KPI Grid -->
    <div class="kpi-grid">
        <div class="card">
            <div class="card-title">حالة الماكينة الحالية</div>
            <div class="card-value" id="val-state" style="color: var(--accent-cyan);">IDLE (0)</div>
        </div>
        <div class="card">
            <div class="card-title">ضغط الهيدروليك</div>
            <div class="card-value"><span id="val-pressure">0.0</span><span class="card-unit">Bar</span></div>
        </div>
        <div class="card">
            <div class="card-title">أمبير المحرك الرئيسي</div>
            <div class="card-value"><span id="val-current">0.0</span><span class="card-unit">Amps</span></div>
        </div>
        <div class="card">
            <div class="card-title">حرارة زيت الهيدروليك</div>
            <div class="card-value"><span id="val-temp">0.0</span><span class="card-unit">°C</span></div>
        </div>
        <div class="card">
            <div class="card-title">عداد القطع في الوردية</div>
            <div class="card-value" id="val-counter" style="color: var(--accent-green);">0</div>
        </div>
        <div class="card">
            <div class="card-title">زمن استجابة الشبكة</div>
            <div class="card-value"><span id="val-latency">0.0</span><span class="card-unit">ms</span></div>
        </div>
    </div>

    <!-- Main Live Analytics Layout -->
    <div class="main-layout">
        <div class="chart-container">
            <h3 style="font-size: 15px; margin-bottom: 15px;">الرسم البياني الحي للبيانات فائقة التردد (20 Hz Telemetry)</h3>
            <canvas id="telemetryChart"></canvas>
        </div>
        <div class="table-container">
            <h3 style="font-size: 15px;">سجل دورات الماكينة المكتشفة تلقائياً (Cycle Analytics)</h3>
            <table>
                <thead>
                    <tr>
                        <th>الدورة #</th>
                        <th>الزمن الكلي</th>
                        <th>أقصى أمبير</th>
                        <th>الحالة والأعطال</th>
                    </tr>
                </thead>
                <tbody id="cycleTableBody">
                    <tr><td colspan="4" style="color: var(--text-muted); text-align: center;">في انتظار اكتمال دورات الماكينة...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const states = { 0: "متوقفة (IDLE)", 1: "إغلاق البستم (CLAMP)", 2: "الكبس/التشغيل (PRESS)", 3: "التبريد (COOL)", 4: "الطرد (EJECT)" };

        // Chart setup
        const ctx = document.getElementById('telemetryChart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: Array(30).fill(''),
                datasets: [
                    { label: 'الضغط (Bar)', borderColor: '#06B6D4', data: Array(30).fill(0), borderWidth: 2, pointRadius: 0, tension: 0.3 },
                    { label: 'الأمبير (Amps)', borderColor: '#F59E0B', data: Array(30).fill(0), borderWidth: 2, pointRadius: 0, tension: 0.3 }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { display: false },
                    y: { grid: { color: '#1F2E4D' }, ticks: { color: '#94A3B8' } }
                },
                plugins: { legend: { labels: { color: '#E2E8F0', font: { family: 'Cairo' } } } }
            }
        });

        // 1-Click Auto Audit
        function startAutoAudit() {
            const ip = document.getElementById('plc-ip').value;
            const station = document.getElementById('station-name').value;
            fetch('/api/audit/start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ ip_address: ip, station_name: station })
            });
        }

        // Toggle Simulator
        let simRunning = false;
        function toggleSimulator() {
            fetch('/api/simulator/toggle', { method: 'POST' })
                .then(r => r.json())
                .then(d => {
                    simRunning = (d.status === 'RUNNING');
                    const btn = document.getElementById('btn-sim');
                    btn.innerHTML = simRunning ? '<span>🛑</span> إيقاف المحاكي' : '<span>🤖</span> تشغيل ماكينة افتراضية للتجربة';
                });
        }

        // Toggle Monitor
        let monitorRunning = false;
        function toggleMonitor() {
            const ip = document.getElementById('plc-ip').value;
            fetch(`/api/monitor/toggle?host=${ip}`, { method: 'POST' })
                .then(r => r.json())
                .then(d => {
                    monitorRunning = (d.status === 'MONITORING_ACTIVE');
                    const btn = document.getElementById('btn-monitor');
                    btn.innerHTML = monitorRunning ? '<span>⏸️</span> إيقاف المراقبة' : '<span>⚡</span> بدء المراقبة الحية';
                });
        }

        // Save Answers
        function saveAnswers() {
            const inputs = document.querySelectorAll('.smart-q-input');
            const answers = {};
            inputs.forEach(inp => answers[inp.dataset.id] = inp.value);
            fetch('/api/audit/answer', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ answers })
            }).then(() => alert('تم حفظ الإجابات وتحديث التقرير بنجاح!'));
        }

        // WebSocket Listener
        const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${wsProto}//${window.location.host}/ws`);

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);

            // Audit Wizard Updates
            if (data.audit) {
                const a = data.audit;
                document.getElementById('progressFill').style.width = `${a.progress_percent}%`;
                document.getElementById('stepText').innerText = a.current_step;

                if (a.result && a.progress_percent >= 100) {
                    document.getElementById('reportBox').classList.add('active');
                    const qBox = document.getElementById('questionsBox');
                    const qCont = document.getElementById('questionsContainer');
                    if (a.result.missing_info_questions && a.result.missing_info_questions.length > 0) {
                        qBox.style.display = 'block';
                        qCont.innerHTML = a.result.missing_info_questions.map(q => `
                            <div class="q-item">
                                <label>${q.question}</label>
                                <input type="text" class="input-field smart-q-input" data-id="${q.id}" value="${q.default || ''}" style="width: 100%;">
                            </div>
                        `).join('');
                    } else {
                        qBox.style.display = 'none';
                    }
                }
            }

            // Live Telemetry Updates
            if (data.telemetry) {
                const t = data.telemetry;
                const stateText = states[t.machine_state] || `حالة ${t.machine_state}`;
                document.getElementById('val-state').innerText = stateText;
                document.getElementById('val-pressure').innerText = t.hydraulic_pressure_bar ? t.hydraulic_pressure_bar.toFixed(1) : '0.0';
                document.getElementById('val-current').innerText = t.motor_current_amps ? t.motor_current_amps.toFixed(1) : '0.0';
                document.getElementById('val-temp').innerText = t.oil_temperature_c ? t.oil_temperature_c.toFixed(1) : '0.0';
                document.getElementById('val-counter').innerText = t.shift_part_counter || '0';
                document.getElementById('val-latency').innerText = t.latency_ms ? t.latency_ms.toFixed(1) : '0.0';

                // Chart update
                chart.data.datasets[0].data.push(t.hydraulic_pressure_bar || 0);
                chart.data.datasets[0].data.shift();
                chart.data.datasets[1].data.push(t.motor_current_amps || 0);
                chart.data.datasets[1].data.shift();
                chart.update('none');
            }

            // Completed Cycles Updates
            if (data.cycles && data.cycles.length > 0) {
                const tbody = document.getElementById('cycleTableBody');
                tbody.innerHTML = data.cycles.slice(0, 8).map(c => `
                    <tr>
                        <td>#${c.cycle_id}</td>
                        <td>${c.duration_sec} ثانية</td>
                        <td>${c.peak_current_amps} أمبير</td>
                        <td><span class="status-pill ${c.anomaly_detected ? 'pill-anomaly' : 'pill-normal'}">${c.anomaly_reasons}</span></td>
                    </tr>
                `).join('');
            }
        };
    </script>
</body>
</html>
"""

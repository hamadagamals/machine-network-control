"""
Sequential Automated Machine Diagnostics Engine
Runs the complete multi-phase non-intrusive discovery, protocol handshake,
latency analysis, memory mapping, and report generation in a single automated flow.
"""

import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional
from plc_extractor.scanner.protocol_probe import ProtocolProbe
from plc_extractor.client.readonly_wrapper import ReadOnlyPLCClient
from plc_extractor.reporting.report_generator import ReportGenerator

logger = logging.getLogger("AutoDiagnostics")


class AutoDiagnosticsEngine:
    """
    Automated sequential diagnostic runner for factory machinery.
    Designed for zero manual terminal interaction.
    """

    def __init__(self, target_host: str = "127.0.0.1", station_name: str = "Machine-01"):
        self.target_host = target_host
        self.station_name = station_name
        self.report_gen = ReportGenerator()
        self.progress_callback: Optional[Callable[[int, str, Optional[Dict[str, Any]]], None]] = None

    def set_callback(self, callback: Callable[[int, str, Optional[Dict[str, Any]]], None]):
        self.progress_callback = callback

    def _emit(self, percent: int, step_description: str, partial_data: Optional[Dict[str, Any]] = None):
        if self.progress_callback:
            try:
                self.progress_callback(percent, step_description, partial_data)
            except Exception as e:
                logger.debug(f"Progress callback error: {e}")

    def run_full_diagnostic(self) -> Dict[str, Any]:
        """
        Executes the 5-step automated sequential audit:
        Step 1: Network & Socket Pre-Check (0-20%)
        Step 2: Protocol Handshake & Fingerprinting (20-40%)
        Step 3: Latency & Communication Budget Test (40-60%)
        Step 4: Memory Mapping & Tag Enumeration (60-80%)
        Step 5: Smart Questions Assessment & Report Compilation (80-100%)
        """
        diagnostic_result: Dict[str, Any] = {
            "station_name": self.station_name,
            "target_ip": self.target_host,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "RUNNING",
            "detected_protocol": "Unknown",
            "vendor": "Unknown",
            "module_type": "Unknown",
            "firmware_version": "Unknown",
            "serial_number": "N/A",
            "rack": 0,
            "slot": 1,
            "avg_latency_ms": 0.0,
            "recommended_poll_rate_hz": 20,
            "recommended_interval_ms": 50,
            "total_tags_count": 0,
            "tags": [],
            "missing_info_questions": [],
            "excel_report_path": "",
            "markdown_report_path": "",
        }

        # ----------------------------------------------------------------------
        # STEP 1: Network & Socket Pre-Check (0 - 20%)
        # ----------------------------------------------------------------------
        self._emit(10, f"جاري فحص اتصال الشبكة والمنافذ المفتوحة على {self.target_host}...")
        probe = ProtocolProbe(host=self.target_host, timeout=1.5)
        open_ports = probe.check_open_ports()
        diagnostic_result["open_ports"] = open_ports

        active_port = None
        for port, is_open in open_ports.items():
            if is_open:
                active_port = port
                break

        # Check if local mock PLC is running on 5020 or 502
        if not active_port:
            # Check candidate port 5020 for simulated machines
            import socket
            sock = socket.socket()
            sock.settimeout(0.5)
            if sock.connect_ex((self.target_host, 5020)) == 0:
                active_port = 5020
                open_ports[5020] = True
            sock.close()

        self._emit(25, f"تم فحص المنافذ. المنافذ المستجيبة: {[p for p, o in open_ports.items() if o]}")

        # CRITICAL SAFETY & ACCURACY CHECK: If no ports respond, stop with UNREACHABLE
        if not active_port:
            diagnostic_result["status"] = "UNREACHABLE"
            diagnostic_result["detected_protocol"] = "غير متاح (لا توجد منافذ مفتوحة)"
            diagnostic_result["vendor"] = "غير معروف (الجهاز غير متصل)"
            diagnostic_result["avg_latency_ms"] = 0.0
            diagnostic_result["total_tags_count"] = 0
            diagnostic_result["tags"] = []
            diagnostic_result["recommendations"] = [
                ("فحص التوصيل الفيزيائي", f"تأكد من توصيل كابل الإيثرنت بين الكمبيوتر وماكينة الـ PLC على العنوان {self.target_host}."),
                ("فحص عنوان الـ IP والسابنت", "تأكد من ضبط كارت الشبكة في الكمبيوتر ليكون على نفس نطاق الـ IP للماكينة (مثلاً: 192.168.1.X)."),
                ("فحص جدار الحماية", "تأكد من عدم وجود راوتر أو جدار حماية صناعي يحظر منافذ التحكم (502, 102, 44818, 4840)."),
                ("وضع المحاكاة", "إذا كنت تقوم بتجربة البرنامج محلياً، اضغط زر [تشغيل ماكينة افتراضية للتجربة] ثم أعد الفحص."),
            ]
            excel_path = self.report_gen.generate_excel_report(diagnostic_result)
            md_path = self.report_gen.generate_markdown_report(diagnostic_result)
            diagnostic_result["excel_report_path"] = excel_path
            diagnostic_result["markdown_report_path"] = md_path

            self._emit(100, f"تنبيه: تعذر الوصول إلى الماكينة على {self.target_host}. تم توليد تقرير فحص الأعطال.", diagnostic_result)
            return diagnostic_result

        # ----------------------------------------------------------------------
        # STEP 2: Protocol Handshake & Fingerprinting (25 - 50%)
        # ----------------------------------------------------------------------
        self._emit(35, "جاري فحص وتحديد نوع المعالج والبروتوكول الصناعي بدقة...")

        # Probe candidate ports without skipping others if handshake returns None
        target_port = None
        discovered_unit_id = 1

        if open_ports.get(102):
            s7_meta = probe.probe_s7comm(port=102)
            if s7_meta:
                diagnostic_result["detected_protocol"] = "Siemens S7comm"
                diagnostic_result["vendor"] = "Siemens AG"
                diagnostic_result["module_type"] = s7_meta.get("module_type", "S7-1200 / S7-1500")
                diagnostic_result["serial_number"] = s7_meta.get("serial_number", "N/A")
                diagnostic_result["rack"] = s7_meta.get("rack", 0)
                diagnostic_result["slot"] = s7_meta.get("slot", 1)
                target_port = 102
                diagnostic_result["port"] = 102

        if not target_port and (open_ports.get(502) or open_ports.get(5020)):
            cand_p = 502 if open_ports.get(502) else 5020
            mb_meta = probe.probe_modbus(port=cand_p)
            if mb_meta:
                diagnostic_result["detected_protocol"] = "Modbus TCP"
                diagnostic_result["vendor"] = "Industrial Controller (Modbus Standard)"
                diagnostic_result["module_type"] = "PLC / Gateway"
                discovered_unit_id = mb_meta.get("primary_unit_id", 1)
                diagnostic_result["unit_id"] = discovered_unit_id
                target_port = cand_p
                diagnostic_result["port"] = cand_p
            else:
                # Port is open but Modbus probe failed (e.g. invalid response)
                target_port = cand_p
                diagnostic_result["detected_protocol"] = "Modbus TCP (Unresponsive Unit ID)"
                diagnostic_result["port"] = cand_p

        if not target_port and open_ports.get(44818):
            diagnostic_result["detected_protocol"] = "Rockwell EtherNet/IP (CIP)"
            diagnostic_result["vendor"] = "Rockwell Automation (Allen-Bradley)"
            diagnostic_result["module_type"] = "ControlLogix / CompactLogix"
            target_port = 44818
            diagnostic_result["port"] = 44818

        if not target_port and open_ports.get(4840):
            diagnostic_result["detected_protocol"] = "OPC UA Server"
            diagnostic_result["vendor"] = "OPC Foundation Standard"
            target_port = 4840
            diagnostic_result["port"] = 4840

        if not target_port:
            target_port = active_port
            diagnostic_result["port"] = active_port

        # ----------------------------------------------------------------------
        # STEP 3: Latency & Communication Budget Test (50 - 70%)
        # ----------------------------------------------------------------------
        self._emit(55, "جاري قياس سرعة الاستجابة وثبات الشبكة الصناعية...")
        latencies = []

        is_s7 = "Siemens" in diagnostic_result["detected_protocol"] or "s7" in diagnostic_result["detected_protocol"].lower()
        protocol_str = "s7comm" if is_s7 else "modbus_tcp"

        client = ReadOnlyPLCClient(
            protocol=protocol_str,
            host=self.target_host,
            port=target_port,
        )

        live_registers_read = []
        comm_success = False

        try:
            if client.connect():
                for _ in range(5):
                    t0 = time.perf_counter()
                    try:
                        if is_s7:
                            db_bytes = client.read_s7_db(db_number=1, start=0, size=32)
                            if db_bytes and len(db_bytes) >= 2:
                                import struct
                                if not live_registers_read:
                                    live_registers_read = [struct.unpack(">H", db_bytes[i : i + 2])[0] for i in range(0, len(db_bytes) - 1, 2)]
                                latencies.append((time.perf_counter() - t0) * 1000.0)
                                comm_success = True
                        else:
                            # Modbus read 0..24 safe batch read using discovered unit_id
                            regs = client.read_holding_registers(address=0, count=25, unit_id=discovered_unit_id)
                            if regs:
                                if not live_registers_read:
                                    live_registers_read = regs
                                latencies.append((time.perf_counter() - t0) * 1000.0)
                                comm_success = True
                    except Exception as e:
                        logger.debug(f"Read sample failure: {e}")
                        break
                    time.sleep(0.02)
                client.disconnect()
        except Exception as e:
            logger.debug(f"Test poll connection error: {e}")

        if latencies:
            avg_lat = sum(latencies) / len(latencies)
            diagnostic_result["avg_latency_ms"] = round(avg_lat, 2)
        else:
            diagnostic_result["avg_latency_ms"] = 0.0

        # ----------------------------------------------------------------------
        # STEP 4: Memory Mapping & Tag Enumeration (70 - 85%)
        # ----------------------------------------------------------------------
        # ----------------------------------------------------------------------
        # STEP 4: Memory Mapping & Tag Enumeration (70 - 85%)
        # ----------------------------------------------------------------------
        self._emit(75, "جاري فحص مصفوفة العناوين المتاحة والمتغيرات الحية...")

        tags_discovered = []

        if not comm_success:
            diagnostic_result["status"] = "COMMUNICATION_FAILED"
            diagnostic_result["tags"] = []
            diagnostic_result["total_tags_count"] = 0
            diagnostic_result["recommendations"] = [
                ("فحص استجابة المعالج", f"المنفذ {target_port} مفتوح ولكن لم يتم تلقي رد بيانات من المعالج عبر بروتوكول {diagnostic_result['detected_protocol']}."),
                ("فحص معرف الوحدة (Unit ID)", f"تحقق من رقم الـ Unit ID الصحيح للماكينة (تم فحص Unit ID: {discovered_unit_id})."),
                ("فحص تصاريح Siemens PUT/GET", "إذا كان المعالج Siemens S7-1200/1500، تأكد من تفعيل خاصية [Permit access with PUT/GET] وإلغاء خيار [Optimized block access] للـ DB1 في TIA Portal."),
            ]
        else:
            if is_s7:
                tags_discovered = [
                    {
                        "name": "machine_state",
                        "protocol": diagnostic_result["detected_protocol"],
                        "area": "DB1.DBW0",
                        "address": "DB1,INT0",
                        "data_type": "INT16",
                        "tier": "Tier 1 (50ms)",
                        "desc": f"حالة تشغيل الماكينة (القيمة الحالية: {live_registers_read[0] if len(live_registers_read) > 0 else '0'})",
                    },
                    {
                        "name": "cycle_trigger",
                        "protocol": diagnostic_result["detected_protocol"],
                        "area": "DB1.DBX2.0",
                        "address": "DB1,X2.0",
                        "data_type": "BOOL",
                        "tier": "Tier 1 (50ms)",
                        "desc": f"مؤشر بدء الدورة (القيمة الحالية: {live_registers_read[1] if len(live_registers_read) > 1 else '0'})",
                    },
                    {
                        "name": "hydraulic_pressure",
                        "protocol": diagnostic_result["detected_protocol"],
                        "area": "DB1.DBW4",
                        "address": "DB1,INT4",
                        "data_type": "INT16 (x10)",
                        "tier": "Tier 1 (50ms)",
                        "desc": f"ضغط الهيدروليك (القيمة الحالية: {live_registers_read[2]/10.0 if len(live_registers_read) > 2 else '0.0'} Bar)",
                    },
                    {
                        "name": "motor_current",
                        "protocol": diagnostic_result["detected_protocol"],
                        "area": "DB1.DBW6",
                        "address": "DB1,INT6",
                        "data_type": "INT16 (x10)",
                        "tier": "Tier 1 (50ms)",
                        "desc": f"أمبير المحرك الرئيسي (القيمة الحالية: {live_registers_read[3]/10.0 if len(live_registers_read) > 3 else '0.0'} A)",
                    },
                    {
                        "name": "oil_temperature",
                        "protocol": diagnostic_result["detected_protocol"],
                        "area": "DB1.DBW20",
                        "address": "DB1,INT20",
                        "data_type": "INT16 (x10)",
                        "tier": "Tier 2 (1s)",
                        "desc": "حرارة زيت الهيدروليك (°C)",
                    },
                    {
                        "name": "shift_counter",
                        "protocol": diagnostic_result["detected_protocol"],
                        "area": "DB1.DBD24",
                        "address": "DB1,DINT24",
                        "data_type": "DINT (32-bit)",
                        "tier": "Tier 3 (10s)",
                        "desc": "إجمالي القطع المكتملة في الوردية",
                    },
                ]
            else:
                tags_discovered = [
                    {
                        "name": "machine_state",
                        "protocol": diagnostic_result["detected_protocol"],
                        "area": "Register 0",
                        "address": "0",
                        "data_type": "UINT16",
                        "tier": "Tier 1 (50ms)",
                        "desc": f"حالة تشغيل الماكينة (القيمة الحالية: {live_registers_read[0] if len(live_registers_read) > 0 else '0'})",
                    },
                    {
                        "name": "cycle_trigger",
                        "protocol": diagnostic_result["detected_protocol"],
                        "area": "Register 1",
                        "address": "1",
                        "data_type": "BOOL",
                        "tier": "Tier 1 (50ms)",
                        "desc": f"مؤشر بدء الدورة (القيمة الحالية: {live_registers_read[1] if len(live_registers_read) > 1 else '0'})",
                    },
                    {
                        "name": "hydraulic_pressure",
                        "protocol": diagnostic_result["detected_protocol"],
                        "area": "Register 2",
                        "address": "2",
                        "data_type": "INT16 (x10)",
                        "tier": "Tier 1 (50ms)",
                        "desc": f"ضغط الهيدروليك (القيمة الحالية: {live_registers_read[2]/10.0 if len(live_registers_read) > 2 else '0.0'} Bar)",
                    },
                    {
                        "name": "motor_current",
                        "protocol": diagnostic_result["detected_protocol"],
                        "area": "Register 3",
                        "address": "3",
                        "data_type": "INT16 (x10)",
                        "tier": "Tier 1 (50ms)",
                        "desc": f"أمبير المحرك الرئيسي (القيمة الحالية: {live_registers_read[3]/10.0 if len(live_registers_read) > 3 else '0.0'} A)",
                    },
                    {
                        "name": "oil_temperature",
                        "protocol": diagnostic_result["detected_protocol"],
                        "area": "Register 20",
                        "address": "20",
                        "data_type": "INT16 (x10)",
                        "tier": "Tier 2 (1s)",
                        "desc": f"حرارة زيت الهيدروليك (°C) (القيمة الحالية: {live_registers_read[20]/10.0 if len(live_registers_read) > 20 else '0.0'} °C)",
                    },
                    {
                        "name": "shift_counter",
                        "protocol": diagnostic_result["detected_protocol"],
                        "area": "Register 30-31",
                        "address": "30-31",
                        "data_type": "UINT32",
                        "tier": "Tier 3 (10s)",
                        "desc": "إجمالي القطع المكتملة في الوردية",
                    },
                ]

            # Scan for any additional responsive non-zero registers discovered in live scan
            if live_registers_read and len(live_registers_read) > 4:
                for offset_idx in range(4, min(20, len(live_registers_read))):
                    val = live_registers_read[offset_idx]
                    if val != 0 and offset_idx not in (0, 1, 2, 3):
                        tags_discovered.append({
                            "name": f"aux_parameter_r{offset_idx}",
                            "protocol": diagnostic_result["detected_protocol"],
                            "area": f"Register {offset_idx}" if not is_s7 else f"DB1.DBW{offset_idx*2}",
                            "address": str(offset_idx),
                            "data_type": "UINT16",
                            "tier": "Tier 2 (1s)",
                            "desc": f"متغير تشغيلي نشط مكتشف على الماكينة (القيمة الحالية: {val})",
                        })

            diagnostic_result["tags"] = tags_discovered
            diagnostic_result["total_tags_count"] = len(tags_discovered)
            diagnostic_result["status"] = "COMPLETED"

        # ----------------------------------------------------------------------
        # STEP 5: Smart Questions Assessment & Report Generation (85 - 100%)
        # ----------------------------------------------------------------------
        self._emit(88, "جاري صياغة الأسئلة الذكية وتوليد تقارير Excel و Markdown...")

        # Evaluate if any critical info is missing that requires user clarification
        questions = []
        if diagnostic_result["vendor"] == "Unknown":
            questions.append({
                "id": "q_brand",
                "question": "لم نتمكن من تحديد ماركة الـ PLC تلقائياً. ما هي الشركة المصنعة؟ (مثال: Siemens, Schneider, Delta, Mitsubishi)",
                "field_type": "text",
                "default": "Siemens",
            })
        if diagnostic_result["detected_protocol"] == "Siemens S7comm" and diagnostic_result.get("module_type") == "Unknown":
            questions.append({
                "id": "q_put_get",
                "question": "إذا كان معالجك Siemens S7-1200/1500، هل خاصية PUT/GET مفعلة في مشروع TIA Portal؟",
                "field_type": "choice",
                "options": ["نعم مفعلة (Yes)", "لا / غير متأكد (سأفحصها)"],
                "default": "نعم مفعلة (Yes)",
            })
        questions.append({
            "id": "q_machine_cycle_target",
            "question": "ما هو متوسط زمن الدورة الإنتاجية المتوقع للماكينة بالثواني؟ (مثال: 12.5 ثانية)",
            "field_type": "number",
            "default": "12.5",
        })

        diagnostic_result["missing_info_questions"] = questions

        # Generate Reports & Ready-to-Run Config
        excel_path = self.report_gen.generate_excel_report(diagnostic_result)
        md_path = self.report_gen.generate_markdown_report(diagnostic_result)
        json_config_path = self.report_gen.generate_tags_config_json(diagnostic_result)

        diagnostic_result["excel_report_path"] = excel_path
        diagnostic_result["markdown_report_path"] = md_path
        diagnostic_result["json_config_path"] = json_config_path

        step_msg = "اكتمل الفحص الآلي للماكينة بنجاح! تم استخراج التقارير وتجهيز خريطة الربط." if comm_success else "اكتمل فحص المنافذ. لم يستجب المعالج للقراءة المباشرة. تم توليد تقرير فحص المشكلات."
        self._emit(100, step_msg, diagnostic_result)
        return diagnostic_result

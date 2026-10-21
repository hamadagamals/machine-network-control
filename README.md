# Machine Network Control (Industrial PLC Extraction & Cycle Analysis)
> **Safe, High-Frequency, Strictly Read-Only Industrial PLC Data Extraction & Machine Cycle Analytics Pipeline**

[![Industrial Safety](https://img.shields.io/badge/Safety_Profile-Strictly_Read_Only-emerald)](https://github.com/hamadagamals/machine-network-control)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![Storage Engine](https://img.shields.io/badge/Storage-DuckDB%20%7C%20Parquet-orange)](https://duckdb.org)
[![Zero Plant Impact](https://img.shields.io/badge/Plant_Impact-Zero_Overwrites-green)](#zero-plant-impact-guarantee)

---

## 🏭 نظرة عامة على المشروع (Project Overview)

تم تصميم هذا النظام الهندسي لتمكين مهندسي الأتمتة والتشغيل من سحب بيانات ماكينات الإنتاج الصناعية بتردد فائق (High-Frequency 20ms - 100ms) وتحليل أداء دورات الماكينة (Cycle Analysis) واكتشاف الأعطال والمشاكل الميكانيكية مبكراً دون الحاجة لوجود خريطة عناوين الـ PLC (Memory Map) الأصلية، ودون المساس ببرمجة الماكينة إطلاقاً.

---

## 🛡️ الضمانات الهندسية الصارمة لحماية الماكينة (Zero Plant Impact Guarantee)

| المبدأ الهندسي | آلية التحقيق في الكود | النتيجة التشغيلية |
| :--- | :--- | :--- |
| **عزل القراءة فقط (Strict Read-Only)** | كلاس `ReadOnlyPLCClient` يحظر فيزيائياً دوال (`write`, `force`, `download`, `stop`). | يستحيل على البرنامج إرسال أي باكت تعديل للماكينة. |
| **استكشاف العناوين سلبياً (Passive Sniffing)** | قراءة باكتات Wireshark (`.pcapng`) بين الـ HMI والـ PLC عبر منفذ SPAN. | لا يتم فحص أي عنوان عشوائي قد يسبب Stop للمعالج. |
| **حماية زمن دورة المعالج (Scan Time Protection)** | محدد معدل استعلامات (`PLCRateLimiter`) وجلسة اتصال واحدة دائمة. | لا يتم إجهاد كارت الشبكة أو تجويع دورة الـ PLC. |
| **عدم تعديل كود الماكينة** | يعمل النظام كمستمع خارجي (SCADA/HMI Observer). | لا يتطلب تنزيل أي بلوكات أو تعديل TIA Portal أو RSLogix. |

---

## 🏗️ الهيكل البرمجي للمشروع (Architecture)

```text
machine-network-control/
├── config/
│   ├── default_config.yaml         # إعدادات الشبكة ومعدلات السحب ومحددات الأمان
│   └── memory_map.yaml             # خريطة العناوين المستخرجة من باكتات الـ HMI
├── plc_extractor/
│   ├── scanner/
│   │   └── protocol_probe.py       # 1. فحص المنافذ والبروتوكول (Modbus, S7, CIP, OPC UA)
│   ├── discovery/
│   │   └── pcap_memory_mapper.py   # 2. الهندسة العكسية للعناوين من ملفات Wireshark
│   ├── client/
│   │   ├── readonly_wrapper.py     # 3. جدار حماية القراءة فقط (Read-Only Firewall)
│   │   └── rate_limiter.py         # محدد معدل الطلبات لحماية دورة المعالج
│   ├── backup/
│   │   └── plc_snapshot.py         # 4. أخذ نسخ احتياطية للمتغيرات والبلوكات للقراءة فقط
│   ├── acquisition/
│   │   ├── poller.py               # 5. محرك السحب فائق السرعة المتزامن زمنياً
│   │   └── storage_engine.py       # محرك التخزين المفصول (DuckDB & Parquet)
│   ├── analytics/
│   │   └── cycle_analyzer.py       # 6. تحليل دورات الماكينة وكشف شذوذ الأداء
│   └── simulator/
│       └── mock_plc_server.py      # 7. محاكي ماكينة صناعية للاختبار الآمن محلياً
├── ui/
│   └── dashboard.py                # لوحة المراقبة الحية (FastAPI + WebSockets)
├── tests/
│   └── test_safety_and_pipeline.py # الاختبارات الآلية الشاملة
├── requirements.txt                # المكتبات البرمجية المطلوبة
└── main.py                         # واجهة سطر الأوامر المركزية (CLI Orchestrator)
```

---

## 🚀 دليل التشغيل السريع (Quickstart Guide)

### 1. تثبيت المتطلبات (Installation)
```powershell
pip install -r requirements.txt
```

### 2. اختبار جدار الحماية والأمان (Safety Audit)
للتأكد عملياً من أن البرنامج يحظر أي محاولة كتابة أو تعديل:
```powershell
python main.py test-safety
```

### 3. تشغيل المحاكي الافتراضي للاختبار الآمن (Simulation Mode)
لتشغيل ماكينة صناعية افتراضية على جهازك دون الحاجة لماكينة حقيقية:
```powershell
python main.py simulate --port 5020
```

### 4. فحص واكتشاف PLC في المصنع (Protocol Probe)
```powershell
python main.py probe --host 192.168.1.50
```

### 5. استخراج العناوين من كابتشر Wireshark (PCAP Memory Mapping)
```powershell
python main.py map-pcap --pcap data/captures/hmi_traffic.pcapng
```

### 6. بدء المراقبة الحية ولوحة التحكم (Edge Real-Time Monitor)
```powershell
python main.py monitor --host 127.0.0.1 --port 5020 --dashboard
```
افتح المتصفح على: `http://localhost:8088` لمشاهدة البيانات الحية ودورات الماكينة ومؤشرات الأداء.

---

## 📊 البيانات المحللة لكل دورة ماكينة (Cycle KPIs)
- **Total Cycle Time:** زمن الدورة الإجمالي بدقة الميكرو ثانية.
- **Phase Breakdown:** تفصيل زمني لكل مرحلة (إغلاق البستم Clamping -> الكبس Pressing -> التبريد Cooling -> الطرد Ejection).
- **Analog Signatures:** أقصى سحب للأمبير (Peak Current)، أقصى ضغط هيدروليكي (Max Pressure)، استهلاك الطاقة التراكمي (Integral Energy).
- **Golden Cycle Comparison:** مطابقة الدورة الحالية مع الدورة المرجعية المثالية لكشف تآكل الصمامات، أو بطء حركة البساتم، أو زيادة الاحتكاك.

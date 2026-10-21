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
│   ├── reporting/
│   │   └── report_generator.py     # 4. مولد التقارير الشاملة (Excel + Markdown)
│   ├── backup/
│   │   └── plc_snapshot.py         # 5. أخذ نسخ احتياطية للمتغيرات والبلوكات للقراءة فقط
│   ├── acquisition/
│   │   ├── poller.py               # 6. محرك السحب فائق السرعة المتزامن زمنياً
│   │   └── storage_engine.py       # محرك التخزين المفصول (DuckDB & Parquet)
│   ├── analytics/
│   │   └── cycle_analyzer.py       # 7. تحليل دورات الماكينة وكشف شذوذ الأداء
│   └── simulator/
│       └── mock_plc_server.py      # 8. محاكي ماكينة صناعية للاختبار الآمن محلياً
├── ui/
│   └── dashboard.py                # لوحة المراقبة التفاعلية الشاملة (Web Portal)
├── tests/
│   └── test_safety_and_pipeline.py # الاختبارات الآلية الشاملة
├── requirements.txt                # المكتبات البرمجية المطلوبة
└── main.py                         # المدخل الرئيسي للتشغيل التلقائي
```

---

## 🚀 دليل التشغيل بنقرة واحدة (1-Click Web Portal - Zero Terminal)

ببساطة، شغل الأمر التالي بدون أي معاملات:
```powershell
python main.py
```
ثم افتح متصفحك على: **`http://localhost:8088`** لتجد الواجهة التفاعلية الكاملة:
1. اضغط زر **[ 🚀 بدء الفحص الآلي الشامل للماكينة ]**.
2. يقوم النظام بفحص المعالج والمنافذ وسرعة الاستجابة تلقائياً ويعرض شريط تقدم حي.
3. فور الانتهاء، يظهر زران لتحميل:
   - **📥 تقرير Excel مفصل ومنسق بالكامل (`.xlsx`).**
   - **📄 تقرير Text / Markdown جاهز للقراءة والتحليل (`.md`).**
4. يمكنك إرسال التقرير للمهندس أو الذكاء الاصطناعي لفهم أفضل استراتيجية ربط فوراً.

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

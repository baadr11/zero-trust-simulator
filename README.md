# 🛡️ Zero Trust Access Simulator

> **"Never Trust, Always Verify"** — محاكي تفاعلي لنظام أمان Zero Trust مع محرك سياسات كامل

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![HTML](https://img.shields.io/badge/Frontend-HTML%2FCSS%2FJS-E34F26?style=flat&logo=html5&logoColor=white)
![No Backend Required](https://img.shields.io/badge/Hosting-None%20Required-success?style=flat)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat)

---

## 📌 المشكلة

الشركات تتحدث عن **Zero Trust** كمفهوم نظري لكنها لا تفهم كيف يعمل عملياً.

الأنظمة الأمنية التقليدية تعتمد على قاعدة بسيطة:
```
كلمة مرور صحيحة → دخول كامل ✅
```

هذا يعني أنه إذا سُرقت بيانات موظف، المهاجم يحصل على **وصول كامل** لكل شيء.

---

## 💡 الحل: Zero Trust

هذا المشروع يُطبّق نموذج Zero Trust حيث **كل طلب وصول** يُفحص من 7 زوايا:

| الفحص | الوصف |
|-------|-------|
| 🔐 RBAC | هل دور المستخدم يسمح بالوصول؟ |
| 📊 Clearance Level | هل مستوى تصريحه كافٍ؟ |
| 🔑 MFA | هل المصادقة الثنائية مفعّلة؟ |
| 💻 Device Trust | هل الجهاز موثوق؟ |
| 📍 Location | هل الموقع الجغرافي طبيعي؟ |
| 🕐 Time Policy | هل وقت الطلب مشبوه؟ |
| 🚨 Anomaly Detection | هل النمط يشير لهجوم؟ |

---

## ✨ المميزات

- **🧠 Policy Engine** مكتوب بـ Python — يحاكي كيف تعمل الأنظمة الحقيقية
- **⚡ سيناريوهات جاهزة** — اضغط زراً لتجربة سيناريوهات هجوم حقيقية
- **🚨 Attack Simulation** — شاهد كيف يفشل المهاجم حتى لو يمتلك كلمة المرور
- **📊 Risk Score** — نقاط خطورة من 0-100 لكل طلب
- **📋 Audit Log** — سجل كامل لكل المحاولات
- **🔄 Traditional vs Zero Trust** — مقارنة مباشرة
- **🌐 No Server Required** — يعمل محلياً بالكامل

---

## 🗂️ هيكل المشروع

```
zero-trust-simulator/
│
├── backend/
│   └── policy_engine.py      # 🧠 محرك السياسات — القلب الحقيقي
│
├── frontend/
│   └── index.html            # 🖥️ الواجهة التفاعلية الكاملة
│
└── README.md
```

---

## 🚀 كيف تشغّله

### الواجهة (بدون أي تثبيت)
```bash
# افتح الملف مباشرة في المتصفح
open frontend/index.html
```

### محرك السياسات (Python)
```bash
# تشغيل الـ demo مع 5 سيناريوهات
python backend/policy_engine.py
```

**Output:**
```
══════════════════════════════════════════════════════════
  ZERO TRUST POLICY ENGINE - CLI DEMO
══════════════════════════════════════════════════════════

────────────────────────────────────────────────────────
  ✅ سيناريو طبيعي - مدير من المكتب
────────────────────────────────────────────────────────
  القرار: ✅ ALLOWED  |  Risk Score: 0/100
  المستخدم: أحمد المنصور (admin)
  المورد: ملفات سرية [CRITICAL]

  [✓] التحقق من الدور (RBAC)       → دور 'admin' مسموح له
  [✓] مستوى التصريح                → المستوى 3 ≥ المطلوب 3
  [✓] المصادقة الثنائية (MFA)      → MFA مفعّل ✓
  [✓] نوع الجهاز (Device Trust)    → جهاز الشركة ← موثوق
  [✓] الموقع الجغرافي              → داخل المكتب ← موثوق
  [✓] وقت الوصول                   → أوقات الدوام ← طبيعي

────────────────────────────────────────────────────────
  🚨 هجوم: بيانات مسروقة
────────────────────────────────────────────────────────
  القرار: 🚫 DENIED  |  Risk Score: 100/100

  [✓] RBAC          → بيانات صحيحة (المهاجم يمتلك كلمة المرور)
  [✗] Device Trust  → جهاز مجهول ← رفض تلقائي!
  [✗] Location      → موقع مجهول ← خطر!
  [✗] Time Policy   → منتصف الليل ← مشبوه!
  [✗] Anomaly       → بيانات مسروقة محتملة — Zero Trust يوقف الهجوم!
```

---

## 🎯 السيناريوهات المدعومة

| السيناريو | النتيجة | السبب |
|-----------|---------|-------|
| مدير من المكتب بـ MFA | ✅ مسموح | كل الفحوصات نجحت |
| موظفة تطلب ملفات سرية | 🚫 مرفوض | RBAC وClearance فشلا |
| مدير بدون MFA | 🚫 مرفوض | MFA إلزامي للموارد الحساسة |
| بيانات مسروقة في منتصف الليل | 🚫 مرفوض | Anomaly Detection كشف النمط |
| زائر على لوحة عامة | ✅ مسموح | المورد لا يتطلب صلاحيات عالية |

---

## 🔍 كيف يعمل Policy Engine

```python
# كل طلب وصول يمر بـ PolicyEngine.evaluate()
engine = PolicyEngine()

decision = engine.evaluate(
    user=USERS["admin"],
    resource=RESOURCES["secret_files"],
    context=AccessContext(
        device="managed",
        location="office",
        time_period="work_hours",
        mfa_active=True
    )
)

print(decision.allowed)     # True
print(decision.risk_score)  # 0
print(decision.to_dict())   # JSON كامل
```

---

## 📚 المفاهيم المُطبَّقة

هذا المشروع يُغطي المواضيع التالية من مقرر أمن الشبكات:

- **Zero Trust Architecture** (NIST SP 800-207)
- **Role-Based Access Control (RBAC)**
- **Multi-Factor Authentication (MFA)**
- **Anomaly Detection & Threat Intelligence**
- **Risk-Based Access Control**
- **Principle of Least Privilege**

---

## 🛠️ التقنيات المستخدمة

| Layer | Technology |
|-------|-----------|
| Policy Engine | Python 3.10+ (No dependencies) |
| Frontend | HTML5 + CSS3 + Vanilla JavaScript |
| Fonts | JetBrains Mono + Cairo |
| Hosting | None (runs locally) |

---

## 🤝 المساهمة

هذا مشروع مفتوح للتطوير. يمكنك:
- إضافة موارد أو مستخدمين جدد
- تعديل قواعد السياسات في `policy_engine.py`
- إضافة فحوصات أمنية إضافية

---

## 👨‍💻 المطور

**Bader Alotaibi** — 

---

## 📄 الترخيص

MIT License — استخدم الكود بحرية مع الإشارة للمصدر.

---

<div align="center">
  <sub> · Zero Trust Simulator · <strong>Bader Alotaibi</strong></sub>
</div>

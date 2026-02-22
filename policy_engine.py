"""
Zero Trust Policy Engine
========================
This is the core of the simulator. Every access request goes through
a multi-factor policy evaluation before a decision is made.

Author: Bader Alotaibi
Course: Network Security / Cybersecurity
"""

from dataclasses import dataclass, field
from typing import Literal, List
from datetime import datetime
import json
import uuid


# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────

Role = Literal["admin", "employee", "guest"]
Device = Literal["managed", "personal", "unknown"]
Location = Literal["office", "home", "unknown"]
TimePeriod = Literal["work_hours", "after_hours", "midnight"]
ResourceName = Literal["secret_files", "api", "database", "public_dashboard"]


@dataclass
class User:
    id: str
    name: str
    role: Role
    email: str
    clearance_level: int  # 1=guest, 2=employee, 3=admin


@dataclass
class Resource:
    id: ResourceName
    name: str
    min_clearance: int
    requires_mfa: bool
    allowed_roles: List[Role]
    sensitivity: Literal["low", "medium", "high", "critical"]


@dataclass
class AccessContext:
    device: Device
    location: Location
    time_period: TimePeriod
    mfa_active: bool
    is_stolen_credentials: bool = False  # for attack simulation


@dataclass
class PolicyCheck:
    name: str
    passed: bool
    reason: str
    risk_level: Literal["info", "low", "medium", "high", "critical"]


@dataclass
class PolicyDecision:
    request_id: str
    timestamp: str
    user: User
    resource: Resource
    context: AccessContext
    checks: List[PolicyCheck]
    allowed: bool
    risk_score: int          # 0-100
    blocked_reasons: List[str]

    def to_dict(self):
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "user": {
                "name": self.user.name,
                "role": self.user.role,
                "email": self.user.email
            },
            "resource": {
                "name": self.resource.name,
                "sensitivity": self.resource.sensitivity
            },
            "context": {
                "device": self.context.device,
                "location": self.context.location,
                "time_period": self.context.time_period,
                "mfa_active": self.context.mfa_active,
                "attack_mode": self.context.is_stolen_credentials
            },
            "decision": {
                "allowed": self.allowed,
                "risk_score": self.risk_score,
                "blocked_reasons": self.blocked_reasons
            },
            "checks": [
                {
                    "name": c.name,
                    "passed": c.passed,
                    "reason": c.reason,
                    "risk_level": c.risk_level
                }
                for c in self.checks
            ]
        }


# ─────────────────────────────────────────────
# Static Data (in real system → database)
# ─────────────────────────────────────────────

USERS: dict[str, User] = {
    "admin": User(
        id="u001", name="أحمد المنصور", role="admin",
        email="ahmed@corp.com", clearance_level=3
    ),
    "employee": User(
        id="u002", name="سارة الغامدي", role="employee",
        email="sara@corp.com", clearance_level=2
    ),
    "guest": User(
        id="u003", name="زائر مجهول", role="guest",
        email="guest@unknown.com", clearance_level=1
    ),
}

RESOURCES: dict[str, Resource] = {
    "secret_files": Resource(
        id="secret_files", name="ملفات سرية", min_clearance=3,
        requires_mfa=True, allowed_roles=["admin"],
        sensitivity="critical"
    ),
    "api": Resource(
        id="api", name="Internal API", min_clearance=2,
        requires_mfa=True, allowed_roles=["admin", "employee"],
        sensitivity="high"
    ),
    "database": Resource(
        id="database", name="قاعدة البيانات", min_clearance=3,
        requires_mfa=True, allowed_roles=["admin"],
        sensitivity="critical"
    ),
    "public_dashboard": Resource(
        id="public_dashboard", name="لوحة عامة", min_clearance=1,
        requires_mfa=False, allowed_roles=["admin", "employee", "guest"],
        sensitivity="low"
    ),
}


# ─────────────────────────────────────────────
# Policy Engine
# ─────────────────────────────────────────────

class PolicyEngine:
    """
    Evaluates every access request against multiple security policies.
    This is the heart of Zero Trust: Never Trust, Always Verify.
    """

    def evaluate(self, user: User, resource: Resource, context: AccessContext) -> PolicyDecision:
        checks: List[PolicyCheck] = []
        risk_score = 0

        # ── Check 1: Role-Based Access Control (RBAC) ──
        role_allowed = user.role in resource.allowed_roles
        checks.append(PolicyCheck(
            name="التحقق من الدور (RBAC)",
            passed=role_allowed,
            reason=(
                f"دور '{user.role}' مسموح له بالوصول"
                if role_allowed
                else f"دور '{user.role}' لا يملك صلاحية الوصول لهذا المورد"
            ),
            risk_level="critical" if not role_allowed else "info"
        ))
        if not role_allowed:
            risk_score += 40

        # ── Check 2: Clearance Level ──
        clearance_ok = user.clearance_level >= resource.min_clearance
        checks.append(PolicyCheck(
            name="مستوى التصريح (Clearance Level)",
            passed=clearance_ok,
            reason=(
                f"مستوى المستخدم {user.clearance_level} ≥ المطلوب {resource.min_clearance}"
                if clearance_ok
                else f"مستوى المستخدم {user.clearance_level} أقل من المطلوب {resource.min_clearance}"
            ),
            risk_level="high" if not clearance_ok else "info"
        ))
        if not clearance_ok:
            risk_score += 30

        # ── Check 3: Multi-Factor Authentication ──
        mfa_ok = (not resource.requires_mfa) or context.mfa_active
        checks.append(PolicyCheck(
            name="المصادقة الثنائية (MFA)",
            passed=mfa_ok,
            reason=(
                "MFA مفعّل ✓" if context.mfa_active
                else ("MFA غير مطلوب لهذا المورد" if not resource.requires_mfa
                      else "MFA مطلوب لهذا المورد الحساس ولكنه غير مفعّل!")
            ),
            risk_level="high" if not mfa_ok else "info"
        ))
        if not mfa_ok:
            risk_score += 25

        # ── Check 4: Device Trust ──
        device_scores = {"managed": 0, "personal": 10, "unknown": 35}
        device_risk = device_scores.get(context.device, 35)
        device_ok = context.device != "unknown"
        checks.append(PolicyCheck(
            name="نوع الجهاز (Device Trust)",
            passed=device_ok,
            reason={
                "managed": "جهاز الشركة ← موثوق تماماً",
                "personal": "جهاز شخصي ← مقبول بحذر",
                "unknown": "جهاز مجهول ← رفض تلقائي!"
            }.get(context.device, "مجهول"),
            risk_level="critical" if context.device == "unknown" else ("low" if context.device == "managed" else "medium")
        ))
        risk_score += device_risk
        if not device_ok:
            risk_score += 15  # extra penalty

        # ── Check 5: Location Risk ──
        location_risk_map = {"office": 0, "home": 8, "unknown": 30}
        loc_risk = location_risk_map.get(context.location, 30)
        loc_ok = not (context.location == "unknown" and resource.sensitivity in ["high", "critical"])
        checks.append(PolicyCheck(
            name="الموقع الجغرافي (Location)",
            passed=loc_ok,
            reason={
                "office": "داخل مكاتب الشركة ← موثوق",
                "home": "الوصول من المنزل ← مقبول مع مراقبة",
                "unknown": "موقع مجهول ← خطر على الموارد الحساسة!"
            }.get(context.location, "مجهول"),
            risk_level="critical" if (context.location == "unknown" and resource.sensitivity == "critical")
                       else "medium" if context.location == "unknown" else "info"
        ))
        risk_score += loc_risk
        if not loc_ok:
            risk_score += 10

        # ── Check 6: Time-Based Policy ──
        time_risk_map = {"work_hours": 0, "after_hours": 10, "midnight": 25}
        time_risk = time_risk_map.get(context.time_period, 25)
        time_ok = not (context.time_period == "midnight" and resource.min_clearance >= 2)
        checks.append(PolicyCheck(
            name="وقت الوصول (Time Policy)",
            passed=time_ok,
            reason={
                "work_hours": "ضمن أوقات الدوام الرسمي ← طبيعي",
                "after_hours": "بعد الدوام ← مقبول مع تسجيل",
                "midnight": "منتصف الليل ← نشاط غير اعتيادي! مشبوه."
            }.get(context.time_period, "مجهول"),
            risk_level="high" if context.time_period == "midnight" else "info"
        ))
        risk_score += time_risk
        if not time_ok:
            risk_score += 10

        # ── Check 7: Threat Detection (Stolen Credentials) ──
        if context.is_stolen_credentials:
            # Zero Trust shines here: even with correct password, context betrays the attacker
            attack_blocked = resource.min_clearance >= 2
            checks.append(PolicyCheck(
                name="🚨 كشف التهديدات (Anomaly Detection)",
                passed=not attack_blocked,
                reason=(
                    "نمط الطلب مشبوه: موقع مجهول + جهاز مجهول + وقت غير اعتيادي "
                    "= بيانات مسروقة محتملة! Zero Trust يوقف الهجوم."
                    if attack_blocked
                    else "لم يُكتشف نمط هجوم واضح"
                ),
                risk_level="critical" if attack_blocked else "info"
            ))
            if attack_blocked:
                risk_score += 50

        # ── Final Decision ──
        failed_checks = [c for c in checks if not c.passed]
        blocked_reasons = [c.reason for c in failed_checks]
        risk_score = min(risk_score, 100)  # cap at 100

        # Decision: deny if ANY critical check failed OR risk score too high
        critical_failed = any(c.risk_level == "critical" for c in failed_checks)
        allowed = len(failed_checks) == 0 and risk_score < 60 and not critical_failed

        return PolicyDecision(
            request_id=str(uuid.uuid4())[:8].upper(),
            timestamp=datetime.now().isoformat(),
            user=user,
            resource=resource,
            context=context,
            checks=checks,
            allowed=allowed,
            risk_score=risk_score,
            blocked_reasons=blocked_reasons
        )


# ─────────────────────────────────────────────
# CLI Demo (run directly to test)
# ─────────────────────────────────────────────

if __name__ == "__main__":
    engine = PolicyEngine()

    print("\n" + "="*60)
    print("  ZERO TRUST POLICY ENGINE - CLI DEMO")
    print("="*60)

    test_cases = [
        # (user, resource, device, location, time, mfa, attack, label)
        ("admin",    "secret_files",    "managed", "office",  "work_hours",  True,  False, "✅ سيناريو طبيعي - مدير من المكتب"),
        ("employee", "secret_files",    "managed", "office",  "work_hours",  True,  False, "❌ موظفة تحاول ملفات سرية"),
        ("admin",    "secret_files",    "managed", "office",  "work_hours",  False, False, "❌ مدير بدون MFA"),
        ("admin",    "secret_files",    "unknown", "unknown", "midnight",    True,  True,  "🚨 هجوم: بيانات مسروقة"),
        ("guest",    "public_dashboard","personal","home",    "after_hours", False, False, "✅ زائر على لوحة عامة"),
    ]

    for user_key, res_key, device, location, time, mfa, attack, label in test_cases:
        print(f"\n{'─'*55}")
        print(f"  {label}")
        print(f"{'─'*55}")

        user = USERS[user_key]
        resource = RESOURCES[res_key]
        context = AccessContext(
            device=device, location=location,
            time_period=time, mfa_active=mfa,
            is_stolen_credentials=attack
        )

        decision = engine.evaluate(user, resource, context)

        status = "✅ ALLOWED" if decision.allowed else "🚫 DENIED"
        print(f"  القرار: {status}  |  Risk Score: {decision.risk_score}/100")
        print(f"  المستخدم: {user.name} ({user.role})")
        print(f"  المورد: {resource.name} [{resource.sensitivity.upper()}]")
        print()
        for check in decision.checks:
            icon = "✓" if check.passed else "✗"
            print(f"  [{icon}] {check.name}")
            print(f"      → {check.reason}")

        if decision.blocked_reasons:
            print(f"\n  أسباب الرفض:")
            for r in decision.blocked_reasons:
                print(f"    ⛔ {r}")

    print("\n" + "="*60)
    print("  JSON Output Example:")
    print("="*60)
    engine2 = PolicyEngine()
    d = engine2.evaluate(
        USERS["admin"], RESOURCES["secret_files"],
        AccessContext("managed", "office", "work_hours", True)
    )
    print(json.dumps(d.to_dict(), ensure_ascii=False, indent=2))

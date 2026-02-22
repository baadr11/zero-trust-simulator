// ════════════════════════════════
//   State
// ════════════════════════════════
let selectedUser     = 'admin';
let selectedResource = 'secret_files';
let stats = { total:0, allowed:0, denied:0, riskSum:0 };

// ════════════════════════════════
//   Data (mirrors Python backend)
// ════════════════════════════════
const USERS = {
  admin:    { name:'أحمد المنصور', role:'admin',    clearance:3 },
  employee: { name:'سارة الغامدي', role:'employee', clearance:2 },
  guest:    { name:'زائر مجهول',   role:'guest',    clearance:1 },
};

const RESOURCES = {
  secret_files:     { name:'ملفات سرية',    minClearance:3, requiresMFA:true,  roles:['admin'],                    sensitivity:'critical' },
  api:              { name:'Internal API',   minClearance:2, requiresMFA:true,  roles:['admin','employee'],         sensitivity:'high' },
  database:         { name:'قاعدة البيانات',minClearance:3, requiresMFA:true,  roles:['admin'],                    sensitivity:'critical' },
  public_dashboard: { name:'لوحة عامة',     minClearance:1, requiresMFA:false, roles:['admin','employee','guest'], sensitivity:'low' },
};

// ════════════════════════════════
//   Policy Engine
// ════════════════════════════════
function policyEngine(uKey, rKey, ctx, isAttack) {
  const u = USERS[uKey];
  const r = RESOURCES[rKey];
  const checks = [];
  let risk = 0;

  const add = (name, passed, reason, riskLevel, extraRisk=0) => {
    checks.push({ name, passed, reason, riskLevel });
    if (!passed) risk += extraRisk;
  };

  // 1. RBAC
  const roleOK = r.roles.includes(u.role);
  add('التحقق من الدور (RBAC)', roleOK,
    roleOK ? "دور '" + u.role + "' مسموح له بالوصول"
           : "دور '" + u.role + "' لا يملك صلاحية الوصول لهذا المورد",
    roleOK ? 'info' : 'critical', 40);

  // 2. Clearance
  const clrOK = u.clearance >= r.minClearance;
  add('مستوى التصريح (Clearance)', clrOK,
    clrOK ? 'المستوى ' + u.clearance + ' ≥ المطلوب ' + r.minClearance
          : 'المستوى ' + u.clearance + ' أقل من المطلوب ' + r.minClearance,
    clrOK ? 'info' : 'high', 30);

  // 3. MFA
  const mfaOK = !r.requiresMFA || ctx.mfa === 'yes';
  add('المصادقة الثنائية (MFA)', mfaOK,
    ctx.mfa === 'yes' ? 'MFA مفعّل'
      : (!r.requiresMFA ? 'MFA غير مطلوب لهذا المورد'
                        : 'MFA مطلوب للمورد الحساس ولكنه غير مفعّل!'),
    mfaOK ? 'info' : 'high', 25);

  // 4. Device
  const devLabels = { managed:'جهاز الشركة - موثوق تماماً', personal:'جهاز شخصي - مقبول بحذر', unknown:'جهاز مجهول - رفض تلقائي!' };
  const devMap = { managed:0, personal:10, unknown:35 };
  const devOK = ctx.device !== 'unknown';
  risk += (ctx.device in devMap) ? devMap[ctx.device] : 35;
  add('نوع الجهاز (Device Trust)', devOK,
    devLabels[ctx.device] || 'مجهول',
    ctx.device==='unknown' ? 'critical' : ctx.device==='managed' ? 'low' : 'medium', 15);

  // 5. Location
  const locLabels = { office:'داخل مكاتب الشركة - موثوق', home:'الوصول من المنزل - مقبول مع مراقبة', unknown:'موقع مجهول - خطر على الموارد الحساسة!' };
  const locMap = { office:0, home:8, unknown:30 };
  const locOK = !(ctx.location==='unknown' && ['high','critical'].includes(r.sensitivity));
  risk += (ctx.location in locMap) ? locMap[ctx.location] : 30;
  add('الموقع الجغرافي (Location)', locOK,
    locLabels[ctx.location] || 'مجهول',
    ctx.location==='unknown' && r.sensitivity==='critical' ? 'critical' : ctx.location==='unknown' ? 'medium' : 'info', 10);

  // 6. Time
  const timeLabels = { work_hours:'ضمن أوقات الدوام الرسمي - طبيعي', after_hours:'بعد الدوام - مقبول مع تسجيل', midnight:'منتصف الليل - نشاط غير اعتيادي! مشبوه.' };
  const timeMap = { work_hours:0, after_hours:10, midnight:25 };
  const timeOK = !(ctx.time==='midnight' && r.minClearance >= 2);
  risk += (ctx.time in timeMap) ? timeMap[ctx.time] : 25;
  add('وقت الوصول (Time Policy)', timeOK,
    timeLabels[ctx.time] || 'مجهول',
    ctx.time==='midnight' ? 'high' : 'info', 10);

  // 7. Attack Detection
  if (isAttack) {
    const blocked = r.minClearance >= 2;
    add('Anomaly Detection - كشف التهديدات', !blocked,
      blocked
        ? 'نمط مشبوه: موقع مجهول + جهاز مجهول + منتصف الليل = بيانات مسروقة محتملة! Zero Trust يوقف الهجوم.'
        : 'لم يُكتشف نمط هجوم واضح',
      blocked ? 'critical' : 'info', blocked ? 50 : 0);
    if (blocked) risk += 50;
  }

  risk = Math.min(risk, 100);
  const critFail = checks.some(function(c){ return !c.passed && c.riskLevel==='critical'; });
  const anyFail  = checks.some(function(c){ return !c.passed; });
  const allowed  = !anyFail && !critFail;

  return { allowed, checks, risk, user:u, resource:r };
}

// ════════════════════════════════
//   Run Check
// ════════════════════════════════
function runCheck(isAttack) {
  if (isAttack === undefined) isAttack = false;
  document.getElementById('attackBanner').style.display = isAttack ? 'flex' : 'none';

  var ctx = {
    mfa:      document.getElementById('mfa').value,
    device:   document.getElementById('device').value,
    location: document.getElementById('location').value,
    time:     document.getElementById('timeSlot').value,
  };

  var res = policyEngine(selectedUser, selectedResource, ctx, isAttack);

  stats.total++;
  if (res.allowed) stats.allowed++; else stats.denied++;
  stats.riskSum += res.risk;
  updateStats();

  var cls = res.allowed ? 'allow' : 'deny';
  var passed = res.checks.filter(function(c){ return c.passed; }).length;
  var riskColor = res.risk < 30 ? '#0f9' : res.risk < 60 ? '#fa0' : '#f45';

  var checksHTML = res.checks.map(function(c, i) {
    var badge = !c.passed ? '<span class="risk-badge rb-' + c.riskLevel + '">' + c.riskLevel.toUpperCase() + '</span>' : '';
    return '<li class="check" style="animation-delay:' + (i*0.06) + 's">' +
      '<span class="check-mark">' + (c.passed ? '✅' : '❌') + '</span>' +
      '<div style="flex:1">' +
        '<div class="check-name">' + c.name + '</div>' +
        '<div class="check-reason ' + (c.passed ? 'pass' : 'fail') + '">' + c.reason + '</div>' +
        badge +
      '</div></li>';
  }).join('');

  document.getElementById('resultWrap').innerHTML =
    '<div class="result-box ' + cls + '" style="display:block">' +
      '<div class="result-header">' +
        '<div class="result-icon-big">' + (res.allowed ? '✅' : '🚫') + '</div>' +
        '<div style="flex:1">' +
          '<div class="result-verdict">' + (res.allowed ? 'وصول مسموح' : 'وصول مرفوض') + '</div>' +
          '<div class="result-meta">' + res.user.name + ' - ' + res.resource.name + ' · اجتاز ' + passed + '/' + res.checks.length + ' فحوصات</div>' +
          '<div class="risk-meter" style="margin-top:8px">' +
            '<span style="font-family:var(--mono);font-size:0.65rem;color:var(--text2)">Risk:</span>' +
            '<div class="risk-bar-wrap"><div class="risk-bar-fill" style="width:' + res.risk + '%;background:' + riskColor + '"></div></div>' +
            '<span style="font-family:var(--mono);font-size:0.7rem;color:' + riskColor + ';font-weight:700">' + res.risk + '/100</span>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<ul class="checks-list">' + checksHTML + '</ul>' +
    '</div>';

  addLog(res, isAttack);
}

function runAttack() {
  document.getElementById('location').value = 'unknown';
  document.getElementById('device').value   = 'unknown';
  document.getElementById('timeSlot').value = 'midnight';
  document.getElementById('mfa').value      = 'yes';
  runCheck(true);
}

function updateStats() {
  document.getElementById('sTotal').textContent = stats.total;
  document.getElementById('sAllow').textContent = stats.allowed;
  document.getElementById('sDeny').textContent  = stats.denied;
  document.getElementById('sRisk').textContent  = stats.total ? Math.round(stats.riskSum/stats.total) : '—';
}

function addLog(res, isAttack) {
  var box = document.getElementById('logBox');
  var empty = box.querySelector('.log-empty');
  if (empty) empty.remove();

  var now = new Date().toLocaleTimeString('ar', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  var statusCls = isAttack ? 'attack' : (res.allowed ? 'ok' : 'denied');
  var statusTxt = isAttack ? '[ATTACK]' : (res.allowed ? '[ALLOW]' : '[DENY] ');

  var row = document.createElement('div');
  row.className = 'log-row';
  row.innerHTML =
    '<span class="log-time">' + now + '</span>' +
    '<span class="log-status ' + statusCls + '">' + statusTxt + '</span>' +
    '<span class="log-msg">' + res.user.name + ' - ' + res.resource.name + (isAttack ? ' بيانات مسروقة' : '') + ' · Risk:' + res.risk + '</span>';
  box.insertBefore(row, box.firstChild);
}

// ════════════════════════════════
//   Scenarios
// ════════════════════════════════
var SCENARIOS = {
  normal:     { user:'admin',    res:'secret_files',    loc:'office',  dev:'managed', time:'work_hours', mfa:'yes', attack:false },
  wrong_role: { user:'employee', res:'secret_files',    loc:'office',  dev:'managed', time:'work_hours', mfa:'yes', attack:false },
  no_mfa:     { user:'admin',    res:'secret_files',    loc:'office',  dev:'managed', time:'work_hours', mfa:'no',  attack:false },
  attack:     { user:'admin',    res:'secret_files',    loc:'unknown', dev:'unknown', time:'midnight',   mfa:'yes', attack:true  },
  guest:      { user:'guest',    res:'public_dashboard',loc:'home',    dev:'personal',time:'work_hours', mfa:'no',  attack:false },
};

function loadScenario(key) {
  var s = SCENARIOS[key];
  document.querySelectorAll('.user-card').forEach(function(c){ c.classList.toggle('sel', c.dataset.u === s.user); });
  selectedUser = s.user;
  document.querySelectorAll('.res-item').forEach(function(c){ c.classList.toggle('sel', c.dataset.r === s.res); });
  selectedResource = s.res;
  document.getElementById('location').value = s.loc;
  document.getElementById('device').value   = s.dev;
  document.getElementById('timeSlot').value = s.time;
  document.getElementById('mfa').value      = s.mfa;
  if (s.attack) runAttack(); else runCheck(false);
}

function selectUser(el, key) {
  document.querySelectorAll('.user-card').forEach(function(c){ c.classList.remove('sel'); });
  el.classList.add('sel');
  selectedUser = key;
}

function selectRes(el, key) {
  document.querySelectorAll('.res-item').forEach(function(c){ c.classList.remove('sel'); });
  el.classList.add('sel');
  selectedResource = key;
}

function resetAll() {
  stats = { total:0, allowed:0, denied:0, riskSum:0 };
  updateStats();
  document.getElementById('logBox').innerHTML = '<div class="log-empty">// لا توجد أحداث بعد</div>';
  document.getElementById('resultWrap').innerHTML =
    '<div class="result-empty">' +
      '<div style="font-size:2rem;margin-bottom:10px">🛡️</div>' +
      'اختر المستخدم والمورد وعوامل السياق<br>ثم اضغط "تحقق من الوصول"' +
    '</div>';
  document.getElementById('attackBanner').style.display = 'none';
}

// Init data attributes
document.addEventListener('DOMContentLoaded', function() {
  var userKeys = ['admin','employee','guest'];
  document.querySelectorAll('.user-card').forEach(function(c, i){
    c.dataset.u = userKeys[i];
    c.setAttribute('onclick', "selectUser(this,'" + userKeys[i] + "')");
  });
  var resKeys = ['secret_files','api','database','public_dashboard'];
  document.querySelectorAll('.res-item').forEach(function(c, i){
    c.dataset.r = resKeys[i];
    c.setAttribute('onclick', "selectRes(this,'" + resKeys[i] + "')");
  });
});

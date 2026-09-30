/* ---------- Theme toggle (persisted per-browser, not shared) ---------- */
const themeToggle = document.getElementById('themeToggle');

function applyTheme(theme) {
  if (theme === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
    themeToggle.textContent = '☀️';
  } else {
    document.documentElement.removeAttribute('data-theme');
    themeToggle.textContent = '🌙';
  }
}

(function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem('phishguard-theme'); } catch (e) { /* storage unavailable */ }
  applyTheme(saved === 'dark' ? 'dark' : 'light');
})();

themeToggle.addEventListener('click', () => {
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  const next = isDark ? 'light' : 'dark';
  applyTheme(next);
  try { localStorage.setItem('phishguard-theme', next); } catch (e) { /* storage unavailable */ }
  refreshStats(); // redraw donut track color for new theme
});

/* ---------- Navigation ---------- */
const navItems = document.querySelectorAll('.nav-item');
const panels = document.querySelectorAll('.panel');

function goto(panelId) {
  navItems.forEach(n => n.classList.toggle('active', n.dataset.panel === panelId));
  panels.forEach(p => p.classList.toggle('active', p.id === 'panel-' + panelId));
  window.scrollTo(0, 0);
  if (panelId === 'history') refreshHistory();
}
navItems.forEach(item => item.addEventListener('click', () => goto(item.dataset.panel)));
document.querySelectorAll('[data-goto]').forEach(el => {
  el.addEventListener('click', () => goto(el.dataset.goto));
});

/* Top search: routes to URL Scanner if it looks like a URL, else Message Analyzer */
document.getElementById('topSearch').addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  const val = e.target.value.trim();
  if (!val) return;
  if (/^https?:\/\/|www\.|\.[a-z]{2,}(\/|$)/i.test(val) && !val.includes(' ')) {
    goto('urlscanner');
    document.getElementById('urlInput').value = val;
  } else {
    goto('analyzer');
    document.getElementById('msgInput').value = val;
  }
});

/* ---------- Stats + donut chart ---------- */
const TIER_COLORS = { critical: '#E14C3C', high: '#F2994A', suspicious: '#F2C94C', low: '#1FA971' };

async function refreshStats() {
  try {
    const res = await fetch('/api/stats');
    const s = await res.json();
    document.getElementById('statMessages').textContent = s.messages_analyzed;
    document.getElementById('statThreats').textContent = s.threats_detected;
    document.getElementById('statUrls').textContent = s.urls_scanned;
    document.getElementById('legCritical').textContent = s.critical;
    document.getElementById('legHigh').textContent = s.high;
    document.getElementById('legSuspicious').textContent = s.suspicious;
    document.getElementById('legLow').textContent = s.low;
    drawDonut(s);
  } catch (e) { /* ignore transient errors */ }
}

function drawDonut(s) {
  const total = s.critical + s.high + s.suspicious + s.low;
  document.getElementById('donutTotal').textContent = total;
  const seg = document.getElementById('donutSegments');
  seg.innerHTML = '';
  if (total === 0) return;

  const order = ['critical', 'high', 'suspicious', 'low'];
  const r = 50, circumference = 2 * Math.PI * r;
  let offset = 0;
  order.forEach(tier => {
    const value = s[tier];
    if (!value) return;
    const fraction = value / total;
    const length = fraction * circumference;
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', 60);
    circle.setAttribute('cy', 60);
    circle.setAttribute('r', r);
    circle.setAttribute('fill', 'none');
    circle.setAttribute('stroke', TIER_COLORS[tier]);
    circle.setAttribute('stroke-width', 16);
    circle.setAttribute('stroke-dasharray', `${length} ${circumference - length}`);
    circle.setAttribute('stroke-dashoffset', -offset);
    seg.appendChild(circle);
    offset += length;
  });
}

/* ---------- Activity Log ---------- */
const TYPE_LABEL = { message: 'Message', url: 'URL' };

async function refreshHistory() {
  const wrap = document.getElementById('historyTableWrap');
  try {
    const res = await fetch('/api/history');
    const items = await res.json();
    if (!items.length) {
      wrap.innerHTML = '<div class="result-empty">No analyses yet — try the Message Analyzer or URL Scanner.</div>';
      return;
    }
    let html = '<table class="history-table"><thead><tr><th>Time</th><th>Type</th><th>Input</th><th>Risk</th><th>Score</th></tr></thead><tbody>';
    items.forEach(item => {
      html += `<tr>
        <td class="history-time">${escapeHtml(item.timestamp)}</td>
        <td class="history-type">${TYPE_LABEL[item.type] || item.type}</td>
        <td class="history-preview" title="${escapeHtml(item.preview)}">${escapeHtml(item.preview)}</td>
        <td><span class="history-badge ${item.level}">${escapeHtml(item.label)}</span></td>
        <td>${item.score}</td>
      </tr>`;
    });
    html += '</tbody></table>';
    wrap.innerHTML = html;
  } catch (e) {
    wrap.innerHTML = '<div class="result-empty">Could not reach the server.</div>';
  }
}

document.getElementById('resetHistory').addEventListener('click', async () => {
  if (!confirm('Reset all dashboard stats and activity history? This cannot be undone.')) return;
  try {
    await fetch('/api/reset', { method: 'POST' });
    refreshStats();
    refreshHistory();
  } catch (e) { /* ignore */ }
});

/* ---------- Message Analyzer ---------- */
const msgInput = document.getElementById('msgInput');
const msgCharCount = document.getElementById('msgCharCount');
const msgResultBox = document.getElementById('msgResultBox');

msgInput.addEventListener('input', () => {
  msgCharCount.textContent = `${msgInput.value.length} characters`;
});

document.getElementById('msgClear').addEventListener('click', () => {
  msgInput.value = '';
  msgCharCount.textContent = '0 characters';
  msgResultBox.innerHTML = '<h4>Analysis result</h4><div class="result-empty">Enter a message and click Analyze Message.</div>';
});

document.getElementById('msgExample').addEventListener('click', () => {
  msgInput.value = "Dear Valued Customer,\n\nWe detected unusual sign-in activity on your account. To avoid permanent suspension, you must verify your identity within 24 hours.\n\nClick here to verify: http://192.168.1.25/verify-account\n\nPlease enter your username, password, and OTP. Failure to complete verification within 24 hours will result in account termination.";
  msgCharCount.textContent = `${msgInput.value.length} characters`;
});

document.getElementById('msgAnalyze').addEventListener('click', async () => {
  const text = msgInput.value.trim();
  if (!text) return;
  msgResultBox.innerHTML = '<h4>Analysis result</h4><div class="result-empty">Analyzing…</div>';
  try {
    const res = await fetch('/api/analyze-message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    const result = await res.json();
    renderResult(msgResultBox, result);
    refreshStats();
    refreshHistory();
  } catch (e) {
    msgResultBox.innerHTML = '<h4>Analysis result</h4><div class="result-empty">Could not reach the server. Is app.py running?</div>';
  }
});

/* ---------- URL Scanner ---------- */
const urlInput = document.getElementById('urlInput');
const urlResultBox = document.getElementById('urlResultBox');

document.getElementById('urlClear').addEventListener('click', () => {
  urlInput.value = '';
  urlResultBox.innerHTML = '<h4>Scan result</h4><div class="result-empty">Enter a URL and click Scan URL.</div>';
});

document.getElementById('urlExample').addEventListener('click', () => {
  urlInput.value = 'http://paypa1-secure-verify.tk/login';
});

document.getElementById('urlScan').addEventListener('click', async () => {
  const url = urlInput.value.trim();
  if (!url) return;
  urlResultBox.innerHTML = '<h4>Scan result</h4><div class="result-empty">Scanning…</div>';
  try {
    const res = await fetch('/api/scan-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const result = await res.json();
    renderResult(urlResultBox, result);
    refreshStats();
    refreshHistory();
  } catch (e) {
    urlResultBox.innerHTML = '<h4>Scan result</h4><div class="result-empty">Could not reach the server. Is app.py running?</div>';
  }
});

function renderResult(box, result) {
  if (result.error) {
    box.innerHTML = `<h4>Result</h4><div class="result-empty">${escapeHtml(result.error)}</div>`;
    return;
  }
  let html = `<h4>Result</h4><div class="verdict">
    <span class="verdict-badge ${result.level}">${result.label}</span>
    <span class="verdict-score">Score: ${result.score} · ${result.flags.length} indicator${result.flags.length !== 1 ? 's' : ''} matched</span>
  </div>`;

  if (result.flags.length === 0) {
    html += '<div class="result-empty" style="padding:20px 0;">No common phishing indicators matched. This does not guarantee it\'s safe — always verify unfamiliar requests independently.</div>';
  } else {
    html += '<ul class="flag-list">';
    result.flags.forEach(f => {
      html += `<li class="flag-item"><div class="ft">${escapeHtml(f.category)} — matched "${escapeHtml(f.matched)}"</div><div class="fd">${escapeHtml(f.explain)}</div></li>`;
    });
    html += '</ul>';
  }
  html += '<div class="disclaimer">Rule-based analysis run server-side — not AI, not a definitive verdict.</div>';
  box.innerHTML = html;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/* ---------- Red flag hotspots ---------- */
document.querySelectorAll('.hotspot').forEach(el => {
  el.addEventListener('click', () => {
    const id = el.dataset.flag;
    const ann = document.getElementById('ann-' + id);
    const showing = ann.classList.contains('show');
    document.querySelectorAll('.annotation').forEach(a => a.classList.remove('show'));
    document.querySelectorAll('.hotspot').forEach(h => h.classList.remove('active'));
    if (!showing) { ann.classList.add('show'); el.classList.add('active'); }
  });
});

/* ---------- Quiz ---------- */
const questions = [
  { scenario: "You get an email from your manager's exact address asking you to urgently buy $500 in gift cards for a client and send the codes by reply — she says she's in back-to-back meetings and can't call.",
    options: [
      { text: "Buy the gift cards right away since it's her real address", correct: false },
      { text: "Reply asking for more details", correct: false },
      { text: "Contact her directly through a known number or in person first", correct: true },
      { text: "Ignore the email completely", correct: false } ],
    explain: "Classic BEC framing: urgency, an unusual request, and a reason you can't verify by phone. Even a matching address can be spoofed or compromised — verify through a separate, already-known channel." },
  { scenario: "An email claims to be from your bank and includes your correct name, but the link preview shows a domain you don't recognize.",
    options: [
      { text: "Click it — it knows your real name so it must be legitimate", correct: false },
      { text: "Don't click — go directly to the bank's official site or app instead", correct: true },
      { text: "Forward it to a coworker to check first", correct: false },
      { text: "Reply asking if it's real", correct: false } ],
    explain: "Attackers often personalize spear-phishing using data from prior breaches, so a correct name proves nothing. The mismatched link domain is the real red flag." },
  { scenario: "An unexpected invoice attachment from a known vendor asks you to 'Enable Editing' and 'Enable Content' to view it.",
    options: [
      { text: "Enable content — you recognize the vendor", correct: false },
      { text: "Don't enable macros — verify the invoice through a known contact first", correct: true },
      { text: "Open it in preview mode only, that's always safe", correct: false },
      { text: "Forward to IT with no further action", correct: false } ],
    explain: "'Enable Content' prompts on unexpected attachments are a common way to trigger malicious macros. Verify unusual attachments out-of-band." },
  { scenario: "A text claims a package couldn't be delivered, with a link to 'reschedule' and pay a small redelivery fee.",
    options: [
      { text: "Pay the small fee since it's low-risk", correct: false },
      { text: "Click the link but don't enter payment info", correct: false },
      { text: "Check delivery status directly through the courier's official app", correct: true },
      { text: "Reply STOP to the message", correct: false } ],
    explain: "This is 'smishing' — the small fee feels harmless but is designed to harvest payment details. Verify through the courier's own app." },
  { scenario: "A caller claiming to be IT helpdesk says they detected malware and needs your login credentials to fix it remotely, right now.",
    options: [
      { text: "Give them your password — it sounds official and urgent", correct: false },
      { text: "Hang up and contact IT using the number from your company directory", correct: true },
      { text: "Give them a slightly different password just in case", correct: false },
      { text: "Ask for proof by email, then give the password", correct: false } ],
    explain: "This is 'vishing'. Legitimate IT staff never need your actual password. Hang up and use a verified internal channel." },
];

let current = 0, score = 0;
const qProgress = document.getElementById('qProgress');
const qScenario = document.getElementById('qScenario');
const qOptions = document.getElementById('qOptions');
const qExplain = document.getElementById('qExplain');
const qNext = document.getElementById('qNext');
const quizResult = document.getElementById('quizResult');

function renderQuestion() {
  const q = questions[current];
  qProgress.textContent = `Question ${current + 1} of ${questions.length}`;
  qScenario.textContent = q.scenario;
  qOptions.innerHTML = '';
  qExplain.classList.remove('show');
  qNext.classList.remove('show');
  q.options.forEach(opt => {
    const btn = document.createElement('button');
    btn.className = 'q-option';
    btn.textContent = opt.text;
    btn.addEventListener('click', () => selectAnswer(btn, opt, q));
    qOptions.appendChild(btn);
  });
}

function selectAnswer(btn, opt, q) {
  document.querySelectorAll('.q-option').forEach(b => b.disabled = true);
  document.querySelectorAll('.q-option').forEach(b => {
    if (b.textContent === q.options.find(o => o.correct).text) b.classList.add('correct');
  });
  if (!opt.correct) btn.classList.add('wrong'); else score++;
  qExplain.textContent = q.explain;
  qExplain.classList.add('show');
  qNext.classList.add('show');
  qNext.textContent = current < questions.length - 1 ? 'Next question →' : 'See results →';
}

qNext.addEventListener('click', () => {
  current++;
  if (current < questions.length) renderQuestion(); else showResult();
});

function showResult() {
  qProgress.style.display = 'none'; qScenario.style.display = 'none';
  qOptions.style.display = 'none'; qExplain.style.display = 'none'; qNext.style.display = 'none';
  quizResult.classList.add('show');
  document.getElementById('quizScore').textContent = `${score}/${questions.length}`;
  const v = document.getElementById('quizVerdict');
  if (score === questions.length) v.textContent = "Sharp eye — you caught every scenario.";
  else if (score >= questions.length - 1) v.textContent = "Solid instincts, one to review.";
  else if (score >= questions.length - 2) v.textContent = "Good start — revisit the explanations above.";
  else v.textContent = "Worth another pass through the module before you move on.";
}

document.getElementById('quizRestart').addEventListener('click', () => {
  current = 0; score = 0;
  qProgress.style.display = ''; qScenario.style.display = ''; qOptions.style.display = '';
  qExplain.style.display = ''; qNext.style.display = '';
  quizResult.classList.remove('show');
  renderQuestion();
});

renderQuestion();
refreshStats();

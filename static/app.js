const $ = (id) => document.getElementById(id);

function escapeHtml(str) {
  const map = {'&': '&', '<': '<', '>': '>', '"': '"', "'": '&#039;'};
  return str.replace(/[&<>"']/g, (m) => map[m]);
}

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function shorten(str, maxLen) {
  if (!str) return "";
  const s = String(str);
  return s.length <= maxLen ? s : s.slice(0, maxLen - 1) + "...";
}

const LS_HISTORY_KEY = "scamscout_history_v1";
const LS_THEME_KEY = "scamscout_theme_v1";
const LS_REPORTS_KEY = "scamscout_reports_v1";

function loadJson(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch { return fallback; }
}

function saveJson(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch {}
}

function setTheme(theme) {
  document.body.dataset.theme = theme;
  saveJson(LS_THEME_KEY, { theme });
}

function initTheme() {
  const saved = loadJson(LS_THEME_KEY, null);
  const preferred = window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  setTheme(saved?.theme === "dark" || saved?.theme === "light" ? saved.theme : preferred);
}

function setActiveView(viewName) {
  ["Analyze", "History", "Settings"].forEach(name => {
    const btn = $("nav" + name);
    const el = $("view" + name);
    if (btn) btn.classList.toggle("isActive", name === viewName);
    if (el) el.classList.toggle("isActive", name === viewName);
  });
}

function renderGoldSilverSignals(goldSignals, silverSignals) {
  const root = $("goldSilverSignals");
  if (!root) return;
  const gold = (goldSignals || []).filter(Boolean);
  const silver = (silverSignals || []).filter(Boolean);
  
  if (!gold.length && !silver.length) {
    root.textContent = "No gold/silver company signals found in the job page excerpt.";
    return;
  }
  
  const goldBadges = gold.slice(0, 6).map(g => '<span class="metalBadge gold">' + escapeHtml(g) + '</span>').join("");
  const silverBadges = silver.slice(0, 6).map(s => '<span class="metalBadge silver">' + escapeHtml(s) + '</span>').join("");
  
  root.innerHTML = '<span style="display:inline-block;margin-right:10px;"><b>Gold:</b> ' + gold.length + '</span>' + goldBadges +
    (silverBadges ? '<div style="height:6px;"></div><b>Silver:</b> ' + silver.length : "") + silverBadges;
}

function renderNearRiskFactors(factors) {
  const ul = $("nearRisks");
  if (!ul) return;
  ul.innerHTML = "";
  const items = (factors || []).filter(Boolean);
  if (!items.length) {
    ul.innerHTML = "<li>No near risk factors detected.</li>";
    return;
  }
  items.slice(0, 4).forEach(f => {
    const li = document.createElement("li");
    li.textContent = "\u26A0\uFE0F " + f;
    ul.appendChild(li);
  });
}

function setRiskUI(riskScore, riskBand, verdict, verdictDetail) {
  document.body.dataset.band = riskBand || "Low";
  const bar = $("riskBar");
  if (bar) bar.style.width = riskScore + "%";
  $("riskScore").textContent = String(riskScore ?? 0);
  $("riskBand").textContent = riskBand ?? "Low";

  const dial = $("riskDial");
  if (dial) {
    const pct = Math.max(0, Math.min(100, Number(riskScore ?? 0)));
    dial.style.background = "conic-gradient(#FFD700 " + pct + "%, rgba(255, 195, 0, 0.35) " + pct + "% 100%)";
  }

  const safetyTag = $("safetyVerdict");
  if (safetyTag) {
    const v = verdict || "SAFE";
    document.body.dataset.verdict = v;
    safetyTag.textContent = v === "SAFE" ? "\u2705 " + v : "\u26A0\uFE0F " + v;
    safetyTag.classList.toggle("safe", v === "SAFE");
    safetyTag.classList.toggle("unsafe", v !== "SAFE");
  }
  
  const verdictDetailEl = $("verdictDetail");
  if (verdictDetailEl) verdictDetailEl.textContent = verdictDetail || "";

  if (bar) {
    bar.classList.remove("riskAnim");
    void bar.offsetWidth;
    bar.classList.add("riskAnim");
  }
}

function renderReportUI(jobUrl, verdict) {
  const wrap = $("reportWrap");
  const btn = $("reportRiskBtn");
  const countEl = $("reportRiskCount");
  if (!wrap || !btn || !countEl) return;

  const isRisk = verdict === "AT RISK";
  wrap.style.display = isRisk ? "flex" : "none";
  if (!isRisk) return;

  const reports = loadJson(LS_REPORTS_KEY, {});
  const count = jobUrl && reports[jobUrl] ? (reports[jobUrl].count || 0) : 0;
  countEl.innerHTML = "Reported: <b>" + count + "</b>";
  btn.disabled = false;
  btn.textContent = "Report as risky link";
}

function renderScoreBreakdown(scoreBreakdown) {
  const section = $("scoreBreakdownSection");
  const list = $("scoreBreakdownList");
  if (!section || !list) return;
  list.innerHTML = "";
  
  if (!scoreBreakdown || !scoreBreakdown.length) {
    section.style.display = "none";
    return;
  }
  
  section.style.display = "block";
  scoreBreakdown.forEach(item => {
    const div = document.createElement("div");
    div.className = "scoreBreakdownItem";
    div.innerHTML = '<div class="scoreBreakdownReason">\u26A0\uFE0F ' + escapeHtml(item.reason) + '</div>' +
      '<div class="scoreBreakdownPoints">+' + escapeHtml(String(item.points)) + '</div>';
    list.appendChild(div);
  });
}

function renderFromResult(data) {
  if (!data) return;

  setRiskUI(data.risk_score, data.risk_band, data.verdict, data.verdict_detail);
  
  // Display timing and analysis mode
  const modeLabels = {
    "hybrid": "🔀 Hybrid",
    "nlp": "🤖 NLP",
    "rules": "📋 Rules"
  };
  const modeLabel = modeLabels[data.analysis_mode] || "🔀 Hybrid";
  $("timingMs").textContent = data.timing_ms != null ? `${modeLabel} • ${data.timing_ms} ms` : modeLabel;
  
  $("explanationSummary").textContent = data.explanation_summary || "";

  const redFlags = data.red_flags || [];
  renderRedFlags(redFlags);
  renderSafetyActions(data.safety_actions || []);
  renderScoreBreakdown(data.score_breakdown || []);
  $("preview").innerHTML = highlightRedFlagsInText(data.analysis_excerpt_for_highlight || "", redFlags);
  renderAllMatches(data.matches || []);
  renderSuggestions(data.suggestions || []);
  renderGoldSilverSignals(data.gold_signals || [], data.silver_signals || []);
  renderNearRiskFactors(data.near_risk_factors || []);

  const jobUrl = data?.url_context?.job_url || ($("jobUrl") ? $("jobUrl").value : "");
  renderReportUI(jobUrl, data.verdict);
}

function renderHistory(items) {
  const root = $("historyList");
  if (!root) return;
  root.innerHTML = "";
  
  if (!items || !items.length) {
    root.innerHTML = '<div class="help" style="margin-top:0;">No history yet.</div>';
    return;
  }

  const frag = document.createDocumentFragment();
  items.forEach(it => {
    const item = document.createElement("div");
    item.className = "historyItem";
    item.tabIndex = 0;
    item.setAttribute("role", "button");
    item.addEventListener("click", () => {
      if (it.result) renderFromResult(it.result);
      if ($("jobUrl") && it.jobUrl) $("jobUrl").value = it.jobUrl;
      setActiveView("Analyze");
    });
    item.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") item.click(); });
    
    const verdictClass = it.verdict === "SAFE" ? "safe" : "unsafe";
    const title = it.jobUrl || it.textPreview || "Job text";
    item.innerHTML = '<div class="historyItemTop"><div class="historyVerdict ' + verdictClass + '">' + escapeHtml(it.verdict || "SAFE") + '</div>' +
      '<div class="historyMeta">' + escapeHtml(String(it.risk_score ?? 0)) + ' \u2022 ' + escapeHtml(it.risk_band || "") + '</div></div>' +
      '<div class="historyMeta">' + escapeHtml(title) + '</div>' +
      '<div class="historyMeta">' + escapeHtml(shorten(it.verdict_detail || "", 120)) + '</div>';
    frag.appendChild(item);
  });
  root.appendChild(frag);
}

function clearHistory() {
  saveJson(LS_HISTORY_KEY, []);
  saveJson(LS_REPORTS_KEY, {});
  renderHistory([]);
  const wrap = $("reportWrap");
  if (wrap) wrap.style.display = "none";
}

function renderAllMatches(matches) {
  const root = $("allMatches");
  root.innerHTML = "";
  
  if (!matches || !matches.length) {
    root.innerHTML = '<div class="item"><div class="itemTitle">No rule matches</div><div class="itemDesc">Rule-based signals did not find obvious scam patterns in this text.</div></div>';
    return;
  }

  matches.forEach(m => {
    const phrases = (m.matched_phrases || []).slice(0, 8);
    const item = document.createElement("div");
    item.className = "item";
    const phrasesHtml = phrases.length ? phrases.map(p => '<code>' + escapeHtml(p) + '</code>').join(", ") : "\u2014";
    item.innerHTML = '<div class="itemTitle">' + escapeHtml(m.title || m.rule_id) + '</div>' +
      '<div class="itemDesc">' + escapeHtml(m.description || "") + '</div>' +
      '<div class="itemPoints">Points: ' + escapeHtml(String(m.points ?? "")) + '</div>' +
      '<div class="itemDesc" style="margin-top:8px;">Matched phrases: ' + phrasesHtml + '</div>';
    root.appendChild(item);
  });
}

function renderSuggestions(suggestions) {
  const ul = $("suggestions");
  ul.innerHTML = "";
  
  if (!suggestions || !suggestions.length) {
    ul.innerHTML = '<li>\u274C No specific suggestions\u2014still verify the employer through official channels.</li>';
    return;
  }
  
  suggestions.forEach(s => {
    const li = document.createElement("li");
    li.textContent = "\u26A0\uFE0F " + s;
    ul.appendChild(li);
  });
}

function renderRedFlags(redFlags) {
  const section = $("redFlagsSection");
  const list = $("redFlagsList");
  if (!section || !list) return;
  list.innerHTML = "";
  
  if (!redFlags || !redFlags.length) {
    section.style.display = "none";
    return;
  }
  
  section.style.display = "block";
  redFlags.forEach(flag => {
    const item = document.createElement("div");
    item.className = "redFlagItem";
    item.innerHTML = '<div class="redFlagPhrase">\uD83D\uDEA9 ' + escapeHtml(flag.phrase) + '</div>' +
      '<div class="redFlagReason">' + escapeHtml(flag.reason) + '</div>';
    list.appendChild(item);
  });
}

function renderSafetyActions(safetyActions) {
  const section = $("safetyActionsSection");
  const list = $("safetyActionsList");
  if (!section || !list) return;
  list.innerHTML = "";
  
  if (!safetyActions || !safetyActions.length) {
    section.style.display = "none";
    return;
  }
  
  section.style.display = "block";
  safetyActions.forEach(action => {
    const item = document.createElement("div");
    item.className = "safetyActionItem";
    item.innerHTML = '<div class="safetyActionIcon">\u2714</div><div class="safetyActionText">' + escapeHtml(action) + '</div>';
    list.appendChild(item);
  });
}

function highlightRedFlagsInText(text, redFlags, maxChars = 4200) {
  if (!text) return "";
  let inputText = String(text);
  if (inputText.length > maxChars) inputText = inputText.slice(0, maxChars - 1) + "...";
  
  const redFlagPhrases = (redFlags || []).map(f => f.phrase).filter(p => p && p.length >= 2);
  const unique = Array.from(new Set(redFlagPhrases)).sort((a, b) => b.length - a.length);
  
  let escaped = escapeHtml(inputText);
  unique.slice(0, 15).forEach(phrase => {
    const re = new RegExp(escapeRegExp(phrase), "gi");
    escaped = escaped.replace(re, (match) => '<mark class="red-flag">' + match + '</mark>');
  });
  return escaped;
}

function setLoading(isLoading) {
  const btn = $("analyzeBtn");
  if (btn) {
    btn.disabled = isLoading;
    btn.classList.toggle("isLoading", isLoading);
  }
  
  if (isLoading) {
    $("explanationSummary").textContent = "Analyzing\u2026";
    $("errorBox").style.display = "none";
    const resultsCard = document.querySelector(".card.results");
    if (resultsCard && !resultsCard.querySelector(".loadingOverlay")) {
      const overlay = document.createElement("div");
      overlay.className = "loadingOverlay";
      overlay.innerHTML = '<div class="loadingSpinner"></div><div class="loadingText">Analyzing job posting...</div><div class="loadingSubtext">Checking for scam indicators</div>';
      resultsCard.appendChild(overlay);
    }
  } else {
    const resultsCard = document.querySelector(".card.results");
    if (resultsCard) {
      const overlay = resultsCard.querySelector(".loadingOverlay");
      if (overlay) overlay.remove();
    }
  }
  
  const bar = $("riskBar");
  if (bar) bar.classList.toggle("isLoading", Boolean(isLoading));
}

async function analyzeCurrentText() {
  let jobUrl = $("jobUrl") ? String($("jobUrl").value || "").trim() : "";
  
  if (jobUrl && !/^https?:\/\//i.test(jobUrl)) {
    jobUrl = "https://" + jobUrl;
  }

  if (!jobUrl) {
    $("errorBox").textContent = "Please paste a job URL first (description is optional).";
    $("errorBox").style.display = "block";
    $("errorBox").className = "errorBox";
    return;
  }

  // Get selected analysis mode
  const analysisMode = document.querySelector('input[name="analysisMode"]:checked')?.value || "hybrid";

  setLoading(true);

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ job_url: jobUrl, analysis_mode: analysisMode }),
    });
    const data = await res.json();

    if (!res.ok || data.error) {
      // Handle "not a job site" error with special styling
      if (data.error === "not_a_job_site") {
        $("errorBox").innerHTML = '<div class="notJobSiteIcon">🔍</div>' +
          '<div class="notJobSiteTitle">' + escapeHtml(data.error_message || "Not a Job Site") + '</div>' +
          '<div class="notJobSiteDetail">' + escapeHtml(data.error_detail || "") + '</div>' +
          '<div class="notJobSiteSuggestion">' + escapeHtml(data.suggestion || "") + '</div>';
        $("errorBox").className = "errorBox notJobSiteError";
        $("errorBox").style.display = "block";
        
        // Reset the results panel to show the error state
        setRiskUI(0, "Low", "NOT A JOB SITE", data.verdict_detail || "The provided URL is not recognized as a job-related website.");
        $("explanationSummary").textContent = "Scam Scout only analyzes job postings for potential scams.";
        $("timingMs").textContent = data.timing_ms != null ? "Analysis time: " + data.timing_ms + " ms" : "";
      } else {
        $("errorBox").textContent = data.error || data.error_message || "Analysis failed.";
        $("errorBox").className = "errorBox";
        $("errorBox").style.display = "block";
      }
      setLoading(false);
      return;
    }

    renderFromResult(data);

    const items = loadJson(LS_HISTORY_KEY, []);
    items.unshift({
      id: Date.now(),
      ts: new Date().toISOString(),
      jobUrl,
      risk_score: data.risk_score,
      risk_band: data.risk_band,
      verdict: data.verdict,
      verdict_detail: data.verdict_detail,
      result: data,
    });
    saveJson(LS_HISTORY_KEY, items.slice(0, 12));
    renderHistory(loadJson(LS_HISTORY_KEY, []));

  } catch (e) {
    $("errorBox").textContent = "Request failed: " + (e?.message || String(e));
    $("errorBox").className = "errorBox";
    $("errorBox").style.display = "block";
  } finally {
    setLoading(false);
  }
}

function clearUI() {
  if ($("jobUrl")) $("jobUrl").value = "";
  $("riskBar").style.width = "0%";
  $("riskScore").textContent = "0";
  $("riskBand").textContent = "Low";
  if ($("safetyVerdict")) {
    $("safetyVerdict").textContent = "SAFE";
    $("safetyVerdict").classList.add("safe");
    $("safetyVerdict").classList.remove("unsafe");
  }
  if ($("verdictDetail")) $("verdictDetail").textContent = "";
  $("timingMs").textContent = "";
  $("explanationSummary").innerHTML = "Paste a URL and click <b>Analyze</b>.";
  $("preview").textContent = "";
  $("allMatches").innerHTML = "";
  $("suggestions").innerHTML = "";
  renderGoldSilverSignals([], []);
  renderNearRiskFactors([]);
  const wrap = $("reportWrap");
  if (wrap) wrap.style.display = "none";
  $("errorBox").style.display = "none";
  ["redFlagsSection", "safetyActionsSection", "scoreBreakdownSection"].forEach(id => {
    const el = $(id);
    if (el) el.style.display = "none";
  });
}

function wireUI() {
  $("analyzeBtn").addEventListener("click", analyzeCurrentText);
  $("clearBtn").addEventListener("click", clearUI);
  $("clearHistoryBtn").addEventListener("click", clearHistory);

  const themeBtn = $("themeToggle");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      setTheme(document.body.dataset.theme === "dark" ? "light" : "dark");
    });
  }

  const clearSettings = $("clearHistoryBtnSettings");
  if (clearSettings) clearSettings.addEventListener("click", clearHistory);

  $("navAnalyze")?.addEventListener("click", () => setActiveView("Analyze"));
  $("navHistory")?.addEventListener("click", () => {
    setActiveView("History");
    renderHistory(loadJson(LS_HISTORY_KEY, []));
  });
  $("navSettings")?.addEventListener("click", () => setActiveView("Settings"));

  $("jobUrl")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") analyzeCurrentText();
  });

  $("reportRiskBtn")?.addEventListener("click", () => {
    const jobUrl = $("jobUrl") ? String($("jobUrl").value || "").trim() : "";
    if (!jobUrl) return;
    const reports = loadJson(LS_REPORTS_KEY, {});
    const cur = reports[jobUrl] || {};
    cur.count = (cur.count || 0) + 1;
    cur.lastReportTs = new Date().toISOString();
    reports[jobUrl] = cur;
    saveJson(LS_REPORTS_KEY, reports);
    renderReportUI(jobUrl, document.body.dataset.verdict || "SAFE");
  });
}

wireUI();
clearUI();
initTheme();
renderHistory(loadJson(LS_HISTORY_KEY, []));
setActiveView("Analyze");
/**
 * Phishing Email Detector — script.js  (v2 – DistilBERT Hybrid)
 * =============================================================
 * Two-layer detection engine:
 *
 *   Layer 1 – Rule Engine  (synchronous, instant)
 *     Keyword patterns, URL detection, uppercase/exclamation heuristics,
 *     and sensitive-info pattern matching.  Score 0–10.
 *
 *   Layer 2 – DistilBERT AI  (async, Web Worker + Transformers.js)
 *     Runs `Xenova/distilbert-base-uncased-finetuned-sst-2-english`
 *     entirely in-browser (ONNX Runtime).  Maps NEGATIVE sentiment
 *     confidence → phishing confidence 0–1 → scaled to 0–10.
 *
 *   Hybrid Final Score = 55 % Rule + 45 % AI  (when AI is ready)
 *   Falls back to 100 % Rule score when model is loading or fails.
 */

'use strict';

/* ============================================================
   1. Detection Rules Configuration
   ============================================================ */

const KEYWORD_RULES = [
  { keyword: 'urgent',              score: 0.8, label: 'Urgency language detected ("urgent")' },
  { keyword: 'click here',         score: 0.9, label: 'Deceptive call-to-action ("click here")' },
  { keyword: 'verify account',     score: 1.0, label: 'Account verification request detected' },
  { keyword: 'verify your account',score: 1.0, label: 'Account verification request detected' },
  { keyword: 'password',           score: 0.9, label: 'Password-related request found' },
  { keyword: 'limited time',       score: 0.7, label: 'Fake time pressure ("limited time")' },
  { keyword: 'update your',        score: 0.6, label: 'Misleading update request' },
  { keyword: 'suspended',          score: 0.9, label: 'Account suspension threat detected' },
  { keyword: 'confirm your',       score: 0.7, label: 'Confirmation request detected' },
  { keyword: 'act now',            score: 0.7, label: 'High-pressure tactic ("act now")' },
  { keyword: 'account has been',   score: 0.8, label: 'Account status manipulation detected' },
  { keyword: 'dear customer',      score: 0.5, label: 'Generic greeting ("dear customer") — legitimate emails usually address you by name' },
  { keyword: 'congratulations',    score: 0.5, label: 'Prize / winner bait detected ("congratulations")' },
  { keyword: 'winner',             score: 0.5, label: 'Prize / winner bait detected' },
  { keyword: 'free',               score: 0.4, label: 'Promotional lure word ("free")' },
  { keyword: 'claim your',         score: 0.7, label: 'Prize-claiming language detected' },
];

const SENSITIVE_PATTERNS = [
  { pattern: /social\s+security/i,                   score: 1.0, label: 'Request for Social Security Number (SSN)' },
  { pattern: /credit\s+card/i,                       score: 1.0, label: 'Request for credit card details' },
  { pattern: /bank\s+(account|details|transfer)/i,   score: 1.0, label: 'Banking information request detected' },
  { pattern: /\bssn\b/i,                             score: 1.0, label: 'SSN abbreviation found' },
  { pattern: /pin\s*(number|code)?/i,                score: 0.8, label: 'PIN / passcode request found' },
  { pattern: /date\s+of\s+birth/i,                   score: 0.7, label: 'Date of birth request found' },
  { pattern: /login\s*(credentials|info)/i,          score: 0.9, label: 'Login credentials request detected' },
];

/** High-risk / free TLDs frequently abused in phishing */
const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq',   // free Freenom TLDs
  '.xyz', '.top', '.win', '.racing',    // cheap abuse-prone TLDs
  '.download', '.loan', '.stream',      // common malware TLDs
  '.click', '.link', '.work', '.gdn',
];

/** Common URL-shortening services used to hide true destinations */
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
  'is.gd', 'buff.ly', 'adf.ly', 'short.link', 'rb.gy',
  'cutt.ly', 'shorturl.at', 'tiny.cc', 'su.pr',
];

/** Brand names commonly impersonated in lookalike domains */
const LOOKALIKE_BRANDS = [
  'paypal', 'amazon', 'apple', 'microsoft', 'google',
  'netflix', 'facebook', 'instagram', 'twitter', 'linkedin',
  'dropbox', 'docusign', 'wellsfargo', 'bankofamerica', 'chase',
  'dhl', 'fedex', 'ups', 'usps', 'irs',
];

/* ============================================================
   2. DOM Element References
   ============================================================ */
const emailInput       = document.getElementById('emailInput');
const analyzeBtn       = document.getElementById('analyzeBtn');
const clearBtn         = document.getElementById('clearBtn');
const charCounter      = document.getElementById('char-counter');
const resultSection    = document.getElementById('resultSection');
const riskBadge        = document.getElementById('riskBadge');
const riskIcon         = document.getElementById('riskIcon');
const riskLevel        = document.getElementById('riskLevel');
const scoreValue       = document.getElementById('scoreValue');
const summaryText      = document.getElementById('summaryText');
const issuesList       = document.getElementById('issuesList');
const highlightedEmail = document.getElementById('highlightedEmail');
const suggestionsList  = document.getElementById('suggestionsList');
const aiScoreRow       = document.getElementById('aiScoreRow');
const ruleScoreRow     = document.getElementById('ruleScoreRow');
const hybridScoreRow   = document.getElementById('hybridScoreRow');
const aiScoreBar       = document.getElementById('aiScoreBar');
const ruleScoreBar     = document.getElementById('ruleScoreBar');
const hybridScoreBar   = document.getElementById('hybridScoreBar');
const aiScoreVal       = document.getElementById('aiScoreVal');
const ruleScoreVal     = document.getElementById('ruleScoreVal');
const hybridScoreVal   = document.getElementById('hybridScoreVal');
const breakdownPanel   = document.getElementById('scoreBreakdownPanel');

/* ============================================================
   3. Web Worker — DistilBERT
   ============================================================ */

/** @type {Worker|null} */
let modelWorker = null;
let modelReady  = false;
let requestId   = 0;

/** Pending promise resolvers keyed by request id */
const pendingRequests = new Map();

function initWorker() {
  try {
    modelWorker = new Worker('model-worker.js', { type: 'module' });

    modelWorker.addEventListener('message', (e) => {
      const msg = e.data;

      switch (msg.type) {
        case 'progress':
          setModelStatus('loading', msg.message);
          break;

        case 'ready':
          modelReady = true;
          setModelStatus('ready', 'DistilBERT model ready');
          break;

        case 'result': {
          const resolver = pendingRequests.get(msg.id);
          if (resolver) {
            resolver.resolve(msg);
            pendingRequests.delete(msg.id);
          }
          break;
        }

        case 'error': {
          if (msg.id === -1) {
            // Boot error
            setModelStatus('error', 'Model failed to load');
            return;
          }
          const resolver = pendingRequests.get(msg.id);
          if (resolver) {
            resolver.reject(new Error(msg.message));
            pendingRequests.delete(msg.id);
          }
          break;
        }
      }
    });

    modelWorker.addEventListener('error', () => {
      setModelStatus('error', 'Worker initialisation failed');
    });

  } catch (_) {
    setModelStatus('error', 'Web Workers not supported in this browser');
  }
}

/**
 * Send text to worker for DistilBERT classification.
 * @param {string} text
 * @returns {Promise<{phishingConf: number, label: string}>}
 */
function classifyWithAI(text) {
  return new Promise((resolve, reject) => {
    if (!modelWorker || !modelReady) {
      reject(new Error('Model not ready'));
      return;
    }
    const id = ++requestId;
    pendingRequests.set(id, { resolve, reject });
    modelWorker.postMessage({ type: 'classify', text, id });

    // 30-second timeout guard
    setTimeout(() => {
      if (pendingRequests.has(id)) {
        pendingRequests.get(id).reject(new Error('Inference timeout'));
        pendingRequests.delete(id);
      }
    }, 30_000);
  });
}

/* ============================================================
   5. Utility Helpers
   ============================================================ */

function countOccurrences(text, sub) {
  const escaped = sub.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return (text.match(new RegExp(escaped, 'gi')) || []).length;
}

function uppercasePercent(text) {
  const letters = text.replace(/[^a-zA-Z]/g, '');
  if (!letters.length) return 0;
  const upper = (text.match(/[A-Z]/g) || []).length;
  return (upper / letters.length) * 100;
}

function clamp(val, min, max) {
  return Math.min(Math.max(val, min), max);
}

/* ============================================================
   6. Rule-Based Detection Engine
   ============================================================ */

function analyzeEmailRules(rawText) {
  const text  = rawText.trim();
  const lower = text.toLowerCase();
  let score   = 0;

  const issues      = [];
  const suggestions = new Set();
  const flaggedWords = new Set();

  /* Rule 1: Keywords */
  let keywordScore = 0;
  for (const rule of KEYWORD_RULES) {
    const count = countOccurrences(lower, rule.keyword);
    if (count > 0) {
      keywordScore += clamp(rule.score * count, 0, rule.score * 2);
      issues.push({ icon: '🔑', text: `${rule.label} (found ${count}×)` });
      flaggedWords.add(rule.keyword);
    }
  }
  score += clamp(keywordScore, 0, 4);

  /* Rule 2: URL analysis */
  const urlRegex = /https?:\/\/[^\s"')]+|www\.[^\s"')]+/gi;
  const urls = text.match(urlRegex) || [];

  /**
   * Safely extract hostname from a raw URL string.
   * Falls back to manual splitting when URL constructor isn't available.
   */
  function extractDomain(rawUrl) {
    try {
      const href = rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`;
      return new URL(href).hostname.toLowerCase().replace(/^www\./, '');
    } catch (_) {
      return rawUrl.split('/')[0].replace(/^www\./, '').toLowerCase();
    }
  }

  if (urls.length > 0) {
    // Base URL-presence score (unchanged)
    score += clamp(1 + urls.length * 0.4, 0, 2);
    issues.push({ icon: '🔗', text: `${urls.length} link(s) found in this email — treat all links with caution` });
    suggestions.add('Avoid clicking unknown links — hover to preview the real destination before clicking.');
    urls.forEach(url => flaggedWords.add(url));

    /* ── Rule 2a: External Link Identification ── */
    const uniqueDomains = [...new Set(urls.map(extractDomain))].filter(Boolean);
    if (uniqueDomains.length > 0) {
      uniqueDomains.forEach(domain => {
        issues.push({
          icon: '🌐',
          text: `External link detected → goes to: ${domain}`,
        });
      });
      if (uniqueDomains.length > 1) {
        score += clamp(uniqueDomains.length * 0.3, 0, 1);
        issues.push({
          icon: '🌐',
          text: `${uniqueDomains.length} different external destinations found — legitimate emails rarely link to multiple unrelated domains`,
        });
      }
      suggestions.add('Check every link\'s real destination carefully — the text shown can differ from where the link actually goes.');
    }

    /* ── Rule 2b: Suspicious Domain Detection ── */
    let suspiciousDomainScore = 0;

    for (const domain of uniqueDomains) {
      // 2b-i: IP address used instead of a real domain name
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
        suspiciousDomainScore += 1.5;
        issues.push({
          icon: '⛔',
          text: `Link leads to a raw IP address (${domain}) — real companies always use a proper domain name, not a numeric IP`,
        });
        flaggedWords.add(domain);
      }

      // 2b-ii: Known URL shortener hiding the true destination
      if (URL_SHORTENERS.some(s => domain === s || domain.endsWith('.' + s))) {
        suspiciousDomainScore += 1.2;
        issues.push({
          icon: '⛔',
          text: `Shortened link detected (${domain}) — URL shorteners hide the real destination and are commonly used in phishing`,
        });
        flaggedWords.add(domain);
      }

      // 2b-iii: High-risk TLD
      const domainLower = domain.toLowerCase();
      const riskyTld = SUSPICIOUS_TLDS.find(tld => domainLower.endsWith(tld));
      if (riskyTld) {
        suspiciousDomainScore += 1.0;
        issues.push({
          icon: '⛔',
          text: `Link uses a high-risk domain ending "${riskyTld}" (${domain}) — these are cheap or free and heavily abused by scammers`,
        });
        flaggedWords.add(domain);
      }

      // 2b-iv: Brand lookalike domain (e.g. paypal-login.com, amaz0n.net)
      const matchedBrand = LOOKALIKE_BRANDS.find(brand => {
        // Brand appears in domain but domain is NOT exactly <brand>.com/.net/.org etc.
        const brandInDomain = domainLower.includes(brand);
        const isOfficialDomain = domainLower === `${brand}.com` ||
                                  domainLower === `${brand}.net` ||
                                  domainLower === `${brand}.org` ||
                                  domainLower === `${brand}.co.uk`;
        return brandInDomain && !isOfficialDomain;
      });
      if (matchedBrand) {
        suspiciousDomainScore += 1.3;
        issues.push({
          icon: '⛔',
          text: `Lookalike domain detected (${domain}) — it uses the name "${matchedBrand}" to impersonate a trusted brand`,
        });
        flaggedWords.add(domain);
        suggestions.add(`This link pretends to be from ${matchedBrand} but the domain is not the real one. Do not click.`);
      }

      // 2b-v: Excessive hyphens in domain (common obfuscation trick)
      const hyphenCount = (domain.match(/-/g) || []).length;
      if (hyphenCount >= 3) {
        suspiciousDomainScore += 0.7;
        issues.push({
          icon: '⛔',
          text: `Suspicious domain structure (${domain}) — many hyphens in a domain name are a common sign of a fake site`,
        });
        flaggedWords.add(domain);
      }
    }

    score += clamp(suspiciousDomainScore, 0, 3);
    if (suspiciousDomainScore > 0) {
      suggestions.add('Do not click any links in this email. Go directly to the official website by typing the address yourself.');
    }
  }

  /* Rule 3: Uppercase */
  const uppercasePct = uppercasePercent(text);
  if (uppercasePct > 50) {
    score += 1.5;
    issues.push({ icon: '🔠', text: `Very high uppercase usage (${uppercasePct.toFixed(0)}%) — commonly used to create false urgency` });
  } else if (uppercasePct > 30) {
    score += 0.75;
    issues.push({ icon: '🔠', text: `Elevated uppercase usage (${uppercasePct.toFixed(0)}%)` });
  }

  /* Rule 4: Exclamation marks */
  const exclamations = (text.match(/!/g) || []).length;
  if (exclamations >= 4) {
    score += 1.0;
    issues.push({ icon: '❗', text: `${exclamations} exclamation marks detected — hallmark of alarm-inducing phishing emails` });
    flaggedWords.add('!');
  } else if (exclamations >= 2) {
    score += 0.4;
    issues.push({ icon: '❗', text: `${exclamations} exclamation marks detected` });
  }

  /* Rule 5: Sensitive patterns */
  let sensitiveScore = 0;
  for (const rule of SENSITIVE_PATTERNS) {
    if (rule.pattern.test(text)) {
      sensitiveScore += rule.score;
      issues.push({ icon: '🔐', text: rule.label });
      suggestions.add('Never share sensitive personal or financial information via email.');
    }
  }
  score += clamp(sensitiveScore, 0, 2);

  score = clamp(parseFloat(score.toFixed(1)), 0, 10);

  return { ruleScore: score, issues, suggestions: [...suggestions], flaggedWords: [...flaggedWords] };
}

/* ============================================================
   7. Classification & Hybrid Scoring
   ============================================================ */

/**
 * Build the final classification result from rule and AI scores.
 *
 * @param {number} ruleScore     - 0–10
 * @param {number|null} aiConf   - 0–1 phishing confidence, or null if unavailable
 * @param {boolean} aiUsed
 */
function buildClassification(ruleScore, aiConf, aiUsed) {
  let finalScore;
  let aiScore = null;

  if (aiUsed && aiConf !== null) {
    aiScore    = parseFloat((aiConf * 10).toFixed(1));          // scale 0–1 → 0–10
    finalScore = clamp(parseFloat((ruleScore * 0.55 + aiScore * 0.45).toFixed(1)), 0, 10);
  } else {
    finalScore = ruleScore;
  }

  let level, label, summary;

  if (finalScore <= 3) {
    level   = 'safe';
    label   = '✅ Safe — Low Risk';
    summary = finalScore === 0
      ? 'No suspicious patterns were detected. This email appears to be safe. Always stay cautious and verify the sender if uncertain.'
      : `Only minor indicators were found (score: ${finalScore}/10). The email is likely safe, but exercise normal caution.`;
  } else if (finalScore <= 6) {
    level   = 'warn';
    label   = '⚠️ Suspicious — Medium Risk';
    summary = `Several warning signs were detected (score: ${finalScore}/10). Treat this email with caution. Do not click any links or provide information until you have verified the sender through an independent channel.`;
  } else {
    level   = 'danger';
    label   = '🚨 Phishing — High Risk';
    summary = `High phishing risk detected (score: ${finalScore}/10). This email displays multiple classic phishing characteristics. Do NOT interact with any links or attachments and do NOT provide any personal information. Report and delete this email immediately.`;
  }

  return { finalScore, aiScore, level, label, summary };
}

/**
 * Build suggestion list combining rule suggestions with level-based defaults.
 */
function buildSuggestions(ruleSuggestions, level) {
  const set = new Set(ruleSuggestions);

  if (level === 'safe') {
    set.add("Always verify the sender's email address, even for emails that appear legitimate.");
  } else if (level === 'warn') {
    set.add('Contact the sender through a verified phone number or official website to confirm legitimacy.');
    set.add('Avoid clicking unknown links — hover to preview URLs before clicking.');
    set.add('Report suspicious emails to your IT security or compliance team.');
  } else {
    set.add('Do not click any links or download any attachments from this email.');
    set.add('Never share sensitive personal or financial information via email.');
    set.add("Report this email to your IT/Security team or use your email provider's phishing report button.");
    set.add('Verify sender identity through an official, independently sourced contact.');
    set.add('Consider running a security scan on your device if you already interacted with this email.');
  }
  return [...set];
}

/* ============================================================
   8. Highlight Engine
   ============================================================ */

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function buildHighlightedHtml(text, flaggedWords) {
  if (!flaggedWords.length) return escapeHtml(text);

  const sorted = [...flaggedWords].sort((a, b) => b.length - a.length);
  const escapedParts = sorted.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const combinedRegex = new RegExp(`(${escapedParts.join('|')})`, 'gi');
  const parts = text.split(combinedRegex);

  return parts.map((part, idx) => {
    if (idx % 2 === 1) return `<mark>${escapeHtml(part)}</mark>`;
    return escapeHtml(part);
  }).join('');
}

/* ============================================================
   9. Score Breakdown UI
   ============================================================ */

function renderScoreBreakdown(ruleScore, aiScore, finalScore, aiUsed) {
  if (!breakdownPanel) return;
  breakdownPanel.classList.remove('hidden');

  // Rule bar
  const ruleBarWidth = (ruleScore / 10) * 100;
  ruleScoreBar.style.width = `${ruleBarWidth}%`;
  ruleScoreBar.style.background = scoreToColor(ruleScore);
  ruleScoreVal.textContent = `${ruleScore} / 10`;

  // AI bar
  if (aiUsed && aiScore !== null) {
    aiScoreRow.classList.remove('hidden');
    const aiBarWidth = (aiScore / 10) * 100;
    aiScoreBar.style.width = `${aiBarWidth}%`;
    aiScoreBar.style.background = scoreToColor(aiScore);
    aiScoreVal.textContent = `${aiScore} / 10`;
  } else {
    aiScoreRow.classList.add('hidden');
  }

  // Hybrid / final bar
  const hybridWidth = (finalScore / 10) * 100;
  hybridScoreBar.style.width = `${hybridWidth}%`;
  hybridScoreBar.style.background = scoreToColor(finalScore);
  hybridScoreVal.textContent = `${finalScore} / 10`;
  hybridScoreRow.querySelector('.breakdown-label').innerHTML =
    aiUsed
      ? '⚡ Overall Risk Score <span class="breakdown-hint">(combined result)</span>'
      : '⚡ Overall Risk Score <span class="breakdown-hint">(pattern check only — AI still loading)</span>';
}

function scoreToColor(score) {
  if (score <= 3)  return 'var(--clr-safe)';
  if (score <= 6)  return 'var(--clr-warn)';
  return 'var(--clr-danger)';
}

/* ============================================================
   10. UI Rendering
   ============================================================ */

function renderResult(ruleResult, classification, aiUsed) {
  const { ruleScore, issues, flaggedWords } = ruleResult;
  const { finalScore, aiScore, level, label, summary } = classification;
  const suggestions = buildSuggestions(ruleResult.suggestions, level);

  /* Risk Badge */
  riskBadge.classList.remove('safe', 'warn', 'danger');
  riskBadge.classList.add(level);

  const icons = { safe: '🛡️', warn: '⚠️', danger: '🚨' };
  riskIcon.textContent  = icons[level];
  riskLevel.textContent = label;
  scoreValue.textContent = finalScore;

  /* Summary */
  summaryText.textContent = summary;

  /* Score Breakdown */
  renderScoreBreakdown(ruleScore, aiScore, finalScore, aiUsed);

  /* Issues */
  issuesList.innerHTML = '';
  if (issues.length === 0) {
    const li = document.createElement('li');
    li.className = 'issue-item';
    li.innerHTML = '<span class="issue-icon">✅</span><span class="issue-text">No issues detected.</span>';
    issuesList.appendChild(li);
  } else {
    issues.forEach((issue, i) => {
      const li = document.createElement('li');
      li.className = 'issue-item';
      li.style.animationDelay = `${i * 60}ms`;
      li.innerHTML = `<span class="issue-icon">${issue.icon}</span><span class="issue-text">${escapeHtml(issue.text)}</span>`;
      issuesList.appendChild(li);
    });
  }

  /* Highlighted Email */
  highlightedEmail.innerHTML = buildHighlightedHtml(emailInput.value, flaggedWords);

  /* Suggestions */
  suggestionsList.innerHTML = '';
  suggestions.forEach((s, i) => {
    const li = document.createElement('li');
    li.className = 'suggestion-item';
    li.style.animationDelay = `${i * 60}ms`;
    li.innerHTML = `<span class="suggestion-icon">💡</span><span>${escapeHtml(s)}</span>`;
    suggestionsList.appendChild(li);
  });

  /* Show */
  resultSection.classList.remove('hidden');
  resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ============================================================
   11. Event Handlers
   ============================================================ */

emailInput.addEventListener('input', () => {
  const count = emailInput.value.length;
  charCounter.textContent = `${count.toLocaleString()} character${count !== 1 ? 's' : ''}`;
});

clearBtn.addEventListener('click', () => {
  emailInput.value = '';
  charCounter.textContent = '0 characters';
  resultSection.classList.add('hidden');
  if (breakdownPanel) breakdownPanel.classList.add('hidden');
  emailInput.focus();
});

analyzeBtn.addEventListener('click', async () => {
  const text = emailInput.value.trim();

  if (!text) {
    emailInput.focus();
    emailInput.style.border = '1.5px solid var(--clr-danger)';
    emailInput.style.boxShadow = '0 0 0 3px rgba(239,68,68,0.22)';
    setTimeout(() => {
      emailInput.style.border = '';
      emailInput.style.boxShadow = '';
    }, 1800);
    return;
  }

  /* Loading state */
  analyzeBtn.disabled = true;
  analyzeBtn.classList.add('loading');
  analyzeBtn.innerHTML = '<span class="btn-icon">⏳</span> Scanning…';

  /* ── Step 1: Run rule engine instantly ── */
  const ruleResult = analyzeEmailRules(text);

  /* ── Step 2: Attempt AI classification ── */
  let aiConf   = null;
  let aiUsed   = false;

  if (modelReady) {
    try {
      const aiResult = await classifyWithAI(text);
      aiConf = aiResult.phishingConf;
      aiUsed = true;
    } catch (_) {
      // AI failed — fall back to rule-only
      aiUsed = false;
    }
  }

  /* ── Step 3: Build hybrid classification ── */
  const classification = buildClassification(ruleResult.ruleScore, aiConf, aiUsed);

  /* ── Step 4: Render ── */
  // Brief delay for UX polish (also lets CSS animate in)
  await new Promise(r => setTimeout(r, 400));
  renderResult(ruleResult, classification, aiUsed);

  analyzeBtn.disabled = false;
  analyzeBtn.classList.remove('loading');
  analyzeBtn.innerHTML = '<span class="btn-icon">🔍</span> Analyze Email';
});

emailInput.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    analyzeBtn.click();
  }
});

/* ============================================================
   12. Boot
   ============================================================ */
initWorker();

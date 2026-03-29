/**
 * Phishing Email Detector — script.js
 * ====================================
 * Rule-based phishing detection engine + UI controller.
 *
 * Detection rules assign weighted scores across categories:
 *   1. Suspicious keywords          (up to +4 pts)
 *   2. URL / link presence          (up to +2 pts)
 *   3. Excessive uppercase letters  (up to +1.5 pts)
 *   4. Multiple exclamation marks   (up to +1 pt)
 *   5. Sensitive information requests (up to +2 pts)
 *
 * Total score range: 0 – 10
 *   0 – 3   → Safe       (Low Risk)
 *   3.1 – 6  → Suspicious (Medium Risk)
 *   6.1 – 10 → Phishing   (High Risk)
 */

'use strict';

/* ============================================================
   1. Detection Rules Configuration
   ============================================================ */

/**
 * @typedef {Object} Rule
 * @property {string}   id          - Unique rule identifier
 * @property {string}   label       - Human-readable label for the Issues panel
 * @property {string}   icon        - Emoji icon shown next to the issue
 * @property {RegExp}   pattern     - Regex to test against email text
 * @property {number}   score       - Points added to phishing score when matched
 * @property {string}   suggestion  - Recommendation shown in the suggestions panel
 */

/** Suspicious urgency / action keywords */
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

/** Sensitive information request patterns */
const SENSITIVE_PATTERNS = [
  { pattern: /social\s+security/i,                   score: 1.0, label: 'Request for Social Security Number (SSN)' },
  { pattern: /credit\s+card/i,                       score: 1.0, label: 'Request for credit card details' },
  { pattern: /bank\s+(account|details|transfer)/i,   score: 1.0, label: 'Banking information request detected' },
  { pattern: /\bssn\b/i,                             score: 1.0, label: 'SSN abbreviation found' },
  { pattern: /pin\s*(number|code)?/i,                score: 0.8, label: 'PIN / passcode request found' },
  { pattern: /date\s+of\s+birth/i,                   score: 0.7, label: 'Date of birth request found' },
  { pattern: /login\s*(credentials|info)/i,          score: 0.9, label: 'Login credentials request detected' },
];

/* ============================================================
   2. DOM Element References
   ============================================================ */
const emailInput      = document.getElementById('emailInput');
const analyzeBtn      = document.getElementById('analyzeBtn');
const clearBtn        = document.getElementById('clearBtn');
const charCounter     = document.getElementById('char-counter');
const resultSection   = document.getElementById('resultSection');
const riskBadge       = document.getElementById('riskBadge');
const riskIcon        = document.getElementById('riskIcon');
const riskLevel       = document.getElementById('riskLevel');
const scoreValue      = document.getElementById('scoreValue');
const scoreCircle     = document.getElementById('scoreCircle');
const summaryText     = document.getElementById('summaryText');
const issuesList      = document.getElementById('issuesList');
const highlightedEmail= document.getElementById('highlightedEmail');
const suggestionsList = document.getElementById('suggestionsList');

/* ============================================================
   3. Utility Helpers
   ============================================================ */

/**
 * Count how many times a substring appears in a string (case-insensitive).
 * @param {string} text
 * @param {string} sub
 * @returns {number}
 */
function countOccurrences(text, sub) {
  const escaped = sub.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return (text.match(new RegExp(escaped, 'gi')) || []).length;
}

/**
 * Calculate the percentage of uppercase characters in the text,
 * ignoring non-letter characters.
 * @param {string} text
 * @returns {number} percentage 0–100
 */
function uppercasePercent(text) {
  const letters = text.replace(/[^a-zA-Z]/g, '');
  if (!letters.length) return 0;
  const upper  = (text.match(/[A-Z]/g) || []).length;
  return (upper / letters.length) * 100;
}

/**
 * Clamp a number between min and max.
 * @param {number} val
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function clamp(val, min, max) {
  return Math.min(Math.max(val, min), max);
}

/* ============================================================
   4. Core Detection Engine
   ============================================================ */

/**
 * @typedef {Object} DetectionResult
 * @property {number}   score       - Raw score 0–10
 * @property {string}   level       - 'safe' | 'warn' | 'danger'
 * @property {string}   label       - Display label
 * @property {string}   summary     - Explanation text
 * @property {Array}    issues      - Array of {icon, text} objects
 * @property {string[]} suggestions - Recommendation strings
 * @property {string[]} flaggedWords - All suspicious words/phrases found (for highlighting)
 */

/**
 * Analyse email text and return a full DetectionResult.
 * @param {string} rawText - Raw email body text
 * @returns {DetectionResult}
 */
function analyzeEmail(rawText) {
  const text   = rawText.trim();
  const lower  = text.toLowerCase();
  let   score  = 0;

  const issues      = [];
  const suggestions = new Set();
  const flaggedWords= new Set();

  /* ── Rule 1: Suspicious Keyword Detection ── */
  let keywordScore = 0;

  for (const rule of KEYWORD_RULES) {
    const count = countOccurrences(lower, rule.keyword);
    if (count > 0) {
      const points = clamp(rule.score * count, 0, rule.score * 2); // cap double occurrences
      keywordScore += points;
      issues.push({
        icon: '🔑',
        text: `${rule.label} (found ${count}×)`,
      });
      flaggedWords.add(rule.keyword);
    }
  }
  score += clamp(keywordScore, 0, 4); // cap keyword category at 4 pts

  /* ── Rule 2: URL / Link Detection ── */
  const urlRegex = /https?:\/\/[^\s"')]+|www\.[^\s"')]+/gi;
  const urls     = text.match(urlRegex) || [];

  if (urls.length > 0) {
    const urlScore = clamp(1 + urls.length * 0.4, 0, 2);
    score += urlScore;
    issues.push({
      icon: '🔗',
      text: `${urls.length} URL(s) detected — could be malicious links`,
    });
    suggestions.add('Avoid clicking unknown links — hover to preview URLs before clicking.');
    // Add the actual matched URL strings for highlighting (not generic prefixes)
    urls.forEach(url => flaggedWords.add(url));
  }

  /* ── Rule 3: Excessive Uppercase ── */
  const uppercasePct = uppercasePercent(text);

  if (uppercasePct > 50) {
    score += 1.5;
    issues.push({
      icon: '🔠',
      text: `Very high uppercase usage (${uppercasePct.toFixed(0)}%) — commonly used to create false urgency`,
    });
  } else if (uppercasePct > 30) {
    score += 0.75;
    issues.push({
      icon: '🔠',
      text: `Elevated uppercase usage (${uppercasePct.toFixed(0)}%)`,
    });
  }

  /* ── Rule 4: Excessive Exclamation Marks ── */
  const exclamations = (text.match(/!/g) || []).length;

  if (exclamations >= 4) {
    score += 1.0;
    issues.push({
      icon: '❗',
      text: `${exclamations} exclamation marks detected — hallmark of alarm-inducing phishing emails`,
    });
    flaggedWords.add('!');
  } else if (exclamations >= 2) {
    score += 0.4;
    issues.push({
      icon: '❗',
      text: `${exclamations} exclamation marks detected`,
    });
  }

  /* ── Rule 5: Sensitive Information Requests ── */
  let sensitiveScore = 0;

  for (const rule of SENSITIVE_PATTERNS) {
    if (rule.pattern.test(text)) {
      sensitiveScore += rule.score;
      issues.push({
        icon: '🔐',
        text: rule.label,
      });
      suggestions.add('Never share sensitive personal or financial information via email.');
    }
  }
  score += clamp(sensitiveScore, 0, 2);

  /* ── Normalise Final Score to 0–10 ── */
  score = clamp(parseFloat(score.toFixed(1)), 0, 10);

  /* ── Classify Risk Level ── */
  let level, label, summary;

  if (score <= 3) {
    level   = 'safe';
    label   = '✅ Safe — Low Risk';
    summary = score === 0
      ? 'No suspicious patterns were detected. This email appears to be safe. Always stay cautious and verify the sender if uncertain.'
      : `Only minor indicators were found (score: ${score}/10). The email is likely safe, but exercise normal caution.`;
    suggestions.add('Always verify the sender\'s email address, even for emails that appear legitimate.');
  } else if (score <= 6) {
    level   = 'warn';
    label   = '⚠️ Suspicious — Medium Risk';
    summary = `Several warning signs were detected (score: ${score}/10). Treat this email with caution. Do not click any links or provide any information until you have verified the sender through an independent channel.`;
    suggestions.add('Contact the sender through a verified phone number or official website to confirm legitimacy.');
    suggestions.add('Avoid clicking unknown links — hover to preview URLs before clicking.');
    suggestions.add('Report suspicious emails to your IT security or compliance team.');
  } else {
    level   = 'danger';
    label   = '🚨 Phishing — High Risk';
    summary = `High phishing risk detected (score: ${score}/10). This email displays multiple classic phishing characteristics. Do NOT interact with any links or attachments and do NOT provide any personal information. Report and delete this email immediately.`;
    suggestions.add('Do not click any links or download any attachments from this email.');
    suggestions.add('Never share sensitive personal or financial information via email.');
    suggestions.add('Report this email to your IT/Security team or use your email provider\'s phishing report button.');
    suggestions.add('Verify sender identity through an official, independently sourced contact.');
    suggestions.add('Consider running a security scan on your device if you already interacted with this email.');
  }

  return {
    score,
    level,
    label,
    summary,
    issues,
    suggestions: [...suggestions],
    flaggedWords: [...flaggedWords],
  };
}

/* ============================================================
   5. Highlight Engine
   ============================================================ */

/**
 * Escape HTML special characters to prevent XSS.
 * @param {string} text
 * @returns {string}
 */
function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Wrap all occurrences of flagged words in the email text with <mark> tags.
 * Builds a single combined regex for efficiency.
 *
 * @param {string}   text        - Original email text
 * @param {string[]} flaggedWords - Words/phrases to highlight
 * @returns {string} HTML string safe to set as innerHTML
 */
function buildHighlightedHtml(text, flaggedWords) {
  if (!flaggedWords.length) {
    return escapeHtml(text);
  }

  // Sort by length descending so longer phrases are matched before substrings
  const sorted = [...flaggedWords].sort((a, b) => b.length - a.length);

  const escapedParts = sorted.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const combinedRegex = new RegExp(`(${escapedParts.join('|')})`, 'gi');

  // Escape the whole text first, then restore <mark> tags
  // We split on the regex to preserve matched text casing
  const parts = text.split(combinedRegex);

  return parts.map((part, idx) => {
    // Odd indices are captured groups (matched words)
    if (idx % 2 === 1) {
      return `<mark>${escapeHtml(part)}</mark>`;
    }
    return escapeHtml(part);
  }).join('');
}

/* ============================================================
   6. UI Rendering
   ============================================================ */

/**
 * Re-render the result section with the DetectionResult data.
 * @param {DetectionResult} result
 */
function renderResult(result) {
  /* ── Risk Badge ── */
  // Remove previous state classes
  riskBadge.classList.remove('safe', 'warn', 'danger');
  riskBadge.classList.add(result.level);

  // Icon
  const icons = { safe: '🛡️', warn: '⚠️', danger: '🚨' };
  riskIcon.textContent = icons[result.level];

  // Label & score
  riskLevel.textContent = result.label;
  scoreValue.textContent = result.score;

  /* ── Summary ── */
  summaryText.textContent = result.summary;

  /* ── Issues List ── */
  issuesList.innerHTML = '';

  if (result.issues.length === 0) {
    const li = document.createElement('li');
    li.className = 'issue-item';
    li.innerHTML = '<span class="issue-icon">✅</span><span class="issue-text">No issues detected.</span>';
    issuesList.appendChild(li);
  } else {
    result.issues.forEach((issue, index) => {
      const li = document.createElement('li');
      li.className = 'issue-item';
      li.style.animationDelay = `${index * 60}ms`;
      li.innerHTML = `
        <span class="issue-icon">${issue.icon}</span>
        <span class="issue-text">${escapeHtml(issue.text)}</span>
      `;
      issuesList.appendChild(li);
    });
  }

  /* ── Highlighted Email Preview ── */
  highlightedEmail.innerHTML = buildHighlightedHtml(emailInput.value, result.flaggedWords);

  /* ── Suggestions ── */
  suggestionsList.innerHTML = '';

  result.suggestions.forEach((suggestion, index) => {
    const li = document.createElement('li');
    li.className = 'suggestion-item';
    li.style.animationDelay = `${index * 60}ms`;
    li.innerHTML = `
      <span class="suggestion-icon">💡</span>
      <span>${escapeHtml(suggestion)}</span>
    `;
    suggestionsList.appendChild(li);
  });

  /* ── Show Section ── */
  resultSection.classList.remove('hidden');

  // Smooth scroll to result
  resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ============================================================
   7. Event Handlers
   ============================================================ */

/**
 * Live character counter update.
 */
emailInput.addEventListener('input', () => {
  const count = emailInput.value.length;
  charCounter.textContent = `${count.toLocaleString()} character${count !== 1 ? 's' : ''}`;
});

/**
 * Clear button — resets the form and hides results.
 */
clearBtn.addEventListener('click', () => {
  emailInput.value = '';
  charCounter.textContent = '0 characters';
  resultSection.classList.add('hidden');
  emailInput.focus();
});

/**
 * Analyze button — runs the detection engine and renders the result.
 * Includes a brief simulated "scanning" delay for UX polish.
 */
analyzeBtn.addEventListener('click', () => {
  const text = emailInput.value.trim();

  // Validation — ensure input is not empty
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

  // Show loading state on button
  analyzeBtn.classList.add('loading');
  analyzeBtn.innerHTML = '<span class="btn-icon">⏳</span> Scanning…';

  // Brief delay to simulate analysis (improves perceived responsiveness)
  setTimeout(() => {
    const result = analyzeEmail(text);
    renderResult(result);

    // Restore button state
    analyzeBtn.classList.remove('loading');
    analyzeBtn.innerHTML = '<span class="btn-icon">🔍</span> Analyze Email';
  }, 600);
});

/**
 * Allow Ctrl+Enter shortcut to trigger analysis.
 */
emailInput.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    analyzeBtn.click();
  }
});

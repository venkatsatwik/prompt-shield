/**
 * PromptShield - In-Page Content Script & Dashboard Sync Bridge
 * v1.3.0 — Robust MutationObserver + SPA-aware injection for ChatGPT, Claude, Gemini
 */

(function () {
  'use strict';

  const host = window.location.hostname;
  console.log("🛡️ PromptShield: Initializing content script on", host);

  // ========================================================
  // DASHBOARD BRIDGE: Sync with Vercel Web Dashboard
  // ========================================================
  if (
    host.includes('vercel.app') ||
    host.includes('localhost') ||
    host.includes('127.0.0.1')
  ) {
    console.log("🛡️ PromptShield: Dashboard Bridge connected on", host);

    function syncWithDashboard() {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['stats', 'auditLogs'], (result) => {
          const stats = result.stats || { totalBlocked: 0, platformCounts: {} };
          const auditLogs = result.auditLogs || [];
          window.postMessage({
            type: 'PROMPTSHIELD_SYNC',
            isInstalled: true,
            stats: stats,
            auditLogs: auditLogs
          }, '*');
        });
      }
    }

    window.addEventListener('message', (e) => {
      if (e.data && e.data.type === 'PROMPTSHIELD_PING') {
        syncWithDashboard();
      }
    });

    setTimeout(syncWithDashboard, 150);
    setTimeout(syncWithDashboard, 500);
    return; // Do not run prompt interception on the dashboard itself
  }

  // ========================================================
  // AI PLATFORM DEFENSE (ChatGPT, Claude, Gemini, DeepSeek)
  // ========================================================
  const detector = new SecretDetector();
  const masker = new SecretMasker();

  loadSessionVault();

  let activeAlertCard = null;
  let lastScannedText = '';
  let pendingScanResult = null;
  let currentTargetEl = null;
  let attachedElements = new WeakSet(); // Track already-wired elements

  const platformName =
    host.includes('chatgpt') ? 'ChatGPT' :
    host.includes('openai')  ? 'ChatGPT' :
    host.includes('claude')  ? 'Claude' :
    host.includes('gemini')  ? 'Gemini' :
    host.includes('deepseek')? 'DeepSeek' : 'GenAI';

  // ── Vault helpers ────────────────────────────────────────
  function saveSessionVault() {
    try {
      const obj = {};
      for (const [k, v] of masker.vault.entries()) obj[k] = v;
      sessionStorage.setItem('promptshield_vault', JSON.stringify(obj));
    } catch (e) {}
  }

  function loadSessionVault() {
    try {
      const stored = sessionStorage.getItem('promptshield_vault');
      if (stored) {
        const parsed = JSON.parse(stored);
        for (const k in parsed) masker.vault.set(k, parsed[k]);
        console.log(`🛡️ PromptShield: Loaded ${masker.vault.size} mapping(s) from session.`);
      }
    } catch (e) {}
  }

  // ── Element helpers ──────────────────────────────────────
  function getTextFromElement(el) {
    if (!el) return '';
    if (el.value !== undefined) return el.value;
    return el.innerText || el.textContent || '';
  }

  function setTextToElement(el, text) {
    if (!el) return;
    if (el.value !== undefined) {
      el.value = text;
    } else {
      // For contenteditable: set innerText and dispatch both input events
      el.innerText = text;
    }
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text }));
  }

  // ── Selector: multi-platform input finder ────────────────
  /**
   * Returns the best prompt input element on the current page.
   * Ordered by specificity — ChatGPT, Claude, Gemini, then generic.
   */
  function findPromptInput() {
    const selectors = [
      // ChatGPT (various versions)
      '#prompt-textarea',
      '[data-id="root"][contenteditable="true"]',
      'div[contenteditable="true"][data-virtualkeyboard]',
      'div.ProseMirror[contenteditable="true"]',
      // Claude
      '[data-testid="compose-message-input"]',
      '.ProseMirror[contenteditable="true"]',
      // Gemini
      'rich-textarea .ql-editor',
      'div[aria-label*="Enter a prompt"]',
      'div[aria-label*="Message"]',
      // Generic fallback
      '[contenteditable="true"]',
      'textarea',
    ];

    for (const sel of selectors) {
      try {
        const el = document.querySelector(sel);
        if (el) return el;
      } catch (_) {}
    }
    return null;
  }

  // ── Audit log & storage ──────────────────────────────────
  function logAuditEvent(sanitizedCount, secretTypes) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['auditLogs', 'stats'], (result) => {
        const logs = result.auditLogs || [];
        const stats = result.stats || { totalBlocked: 0, platformCounts: {} };

        logs.unshift({
          id: Date.now(),
          timestamp: new Date().toLocaleTimeString(),
          date: new Date().toLocaleDateString(),
          platform: platformName,
          secretsCount: sanitizedCount,
          categories: secretTypes
        });
        if (logs.length > 100) logs.pop();

        stats.totalBlocked += sanitizedCount;
        stats.platformCounts[platformName] = (stats.platformCounts[platformName] || 0) + sanitizedCount;

        chrome.storage.local.set({ auditLogs: logs, stats: stats });
      });
    }
  }

  // ── Alert card ───────────────────────────────────────────
  function showAlert(inputEl, scanResult) {
    removeAlert();
    currentTargetEl = inputEl;

    const card = document.createElement('div');
    card.id = 'promptshield-floating-alert';
    card.className = 'promptshield-alert-card';

    const tagsHtml = scanResult.secrets
      .map(s => `<span class="promptshield-tag">${s.label}</span>`)
      .join('');

    card.innerHTML = `
      <div class="promptshield-header">
        <div class="promptshield-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          PromptShield: Credentials Detected!
        </div>
        <span class="promptshield-badge-count">${scanResult.totalFound} Secret${scanResult.totalFound > 1 ? 's' : ''}</span>
      </div>
      <div class="promptshield-body">
        This message contains sensitive keys that will leak to ${platformName}:
        <div class="promptshield-secret-tags">${tagsHtml}</div>
      </div>
      <div class="promptshield-actions">
        <button class="promptshield-btn-dismiss" id="ps-btn-dismiss">Allow Unmasked</button>
        <button class="promptshield-btn-sanitize" id="ps-btn-sanitize">
          <span>🎭 Sanitize &amp; Auto-Mask</span>
        </button>
      </div>
    `;

    document.body.appendChild(card);
    activeAlertCard = card;
    positionAlert(inputEl, card);

    card.querySelector('#ps-btn-sanitize').addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const rawText = getTextFromElement(inputEl);
      const masked = masker.mask(rawText, scanResult.secrets);
      setTextToElement(inputEl, masked.sanitizedText);
      saveSessionVault();
      logAuditEvent(scanResult.totalFound, [...new Set(scanResult.secrets.map(s => s.category))]);
      removeAlert();
      lastScannedText = masked.sanitizedText;
    });

    card.querySelector('#ps-btn-dismiss').addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      removeAlert();
      pendingScanResult = null;
    });
  }

  function positionAlert(inputEl, card) {
    if (!inputEl || !card) return;
    const rect = inputEl.getBoundingClientRect();
    const cardHeight = card.offsetHeight || 120;
    const topPos = Math.max(10, rect.top - cardHeight - 14);
    const leftPos = Math.max(16, rect.left);
    const width = Math.min(rect.width || 500, 700);
    card.style.top = `${topPos}px`;
    card.style.left = `${leftPos}px`;
    card.style.width = `${width}px`;
  }

  function removeAlert() {
    if (activeAlertCard) {
      activeAlertCard.remove();
      activeAlertCard = null;
    }
  }

  // ── Core scan ────────────────────────────────────────────
  function checkText(inputEl) {
    if (!inputEl) return;
    const text = getTextFromElement(inputEl);
    if (text === lastScannedText) return;
    lastScannedText = text;

    if (!text || text.trim().length === 0) {
      removeAlert();
      pendingScanResult = null;
      return;
    }

    const result = detector.scan(text);
    if (result.detected) {
      pendingScanResult = result;
      showAlert(inputEl, result);
    } else {
      pendingScanResult = null;
      removeAlert();
    }
  }

  // ── Event wiring ─────────────────────────────────────────
  /**
   * Attaches input/paste listeners to a specific element.
   * Uses WeakSet to avoid double-wiring the same element.
   */
  function wireElement(el) {
    if (!el || attachedElements.has(el)) return;
    attachedElements.add(el);
    console.log("🛡️ PromptShield: Wired input element →", el.tagName, el.id || el.className.substring(0, 40));

    el.addEventListener('input', () => checkText(el), true);
    el.addEventListener('paste', () => {
      setTimeout(() => checkText(el), 80);
    }, true);
  }

  /**
   * Finds the prompt input and wires it. Called on init and by MutationObserver.
   */
  function tryWirePromptInput() {
    const el = findPromptInput();
    if (el) wireElement(el);
  }

  // ── Global fallback listeners ────────────────────────────
  // These catch events on ANY element in case findPromptInput() misses something
  document.addEventListener('input', (e) => {
    const el = findPromptInput() || e.target;
    if (el) checkText(el);
  }, true);

  document.addEventListener('paste', (e) => {
    setTimeout(() => {
      const el = findPromptInput() || document.activeElement;
      if (el) checkText(el);
    }, 80);
  }, true);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && pendingScanResult && pendingScanResult.detected) {
      e.preventDefault();
      e.stopPropagation();
      if (activeAlertCard) {
        activeAlertCard.style.animation = 'promptshield-shake 0.3s ease';
        setTimeout(() => {
          if (activeAlertCard) activeAlertCard.style.animation = '';
        }, 300);
      }
    }
  }, true);

  window.addEventListener('resize', () => {
    if (activeAlertCard && currentTargetEl) positionAlert(currentTargetEl, activeAlertCard);
  });

  // ── MutationObserver: SPA & Dynamic DOM ─────────────────
  /**
   * ChatGPT is a Single-Page App. When you open a new chat, the editor
   * is REMOVED and RE-INSERTED into the DOM. The MutationObserver watches
   * for this and re-wires event listeners automatically.
   */
  const observer = new MutationObserver((mutations) => {
    let shouldCheck = false;
    for (const mutation of mutations) {
      if (mutation.addedNodes.length > 0) {
        shouldCheck = true;
        break;
      }
    }
    if (shouldCheck) tryWirePromptInput();
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  // ── Init: wire on load & retry ───────────────────────────
  tryWirePromptInput();
  setTimeout(tryWirePromptInput, 500);
  setTimeout(tryWirePromptInput, 1500);
  setTimeout(tryWirePromptInput, 3000);

  // ── ROUND-TRIP RESTORATION: Copy-Button Hook ─────────────
  function tryRestoreText(text) {
    if (!text || masker.vault.size === 0) return null;
    let hasToken = false;
    for (const token of masker.vault.keys()) {
      if (text.includes(token) || text.includes(token.replace('<', '&lt;').replace('>', '&gt;'))) {
        hasToken = true;
        break;
      }
    }
    if (!hasToken) return null;
    return masker.restore(text);
  }

  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    const btnText = (btn.innerText || btn.getAttribute('aria-label') || '').toLowerCase();
    const isCopyButton = btnText.includes('copy') || btn.querySelector('svg');
    if (!isCopyButton) return;

    const codeContainer =
      btn.closest('pre, .rounded-md, div[class*="code"]') ||
      btn.parentElement?.parentElement;
    if (!codeContainer) return;

    const codeEl = codeContainer.querySelector('code, pre');
    if (!codeEl) return;

    const rawCode = codeEl.innerText || codeEl.textContent;
    const restored = tryRestoreText(rawCode);
    if (restored && restored !== rawCode) {
      navigator.clipboard.writeText(restored).then(() => {
        showCopyToast();
      }).catch(() => {
        console.warn('🛡️ PromptShield: Clipboard write fallback needed.');
      });
    }
  }, true);

  document.addEventListener('copy', (e) => {
    const selectedText = window.getSelection().toString();
    if (!selectedText) return;
    const restored = tryRestoreText(selectedText);
    if (restored && restored !== selectedText) {
      e.clipboardData.setData('text/plain', restored);
      e.preventDefault();
      showCopyToast();
    }
  });

  function showCopyToast() {
    const existing = document.getElementById('ps-toast');
    if (existing) existing.remove();
    const toast = document.createElement('div');
    toast.id = 'ps-toast';
    toast.style.cssText = `
      position: fixed !important; bottom: 28px !important; right: 28px !important;
      z-index: 2147483647 !important;
      background: linear-gradient(135deg, #10b981 0%, #059669 100%) !important;
      color: #ffffff !important; padding: 12px 20px !important;
      border-radius: 10px !important; font-size: 13px !important;
      font-weight: 700 !important; font-family: -apple-system, sans-serif !important;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5), 0 0 20px rgba(16,185,129,0.4) !important;
      display: flex !important; align-items: center !important; gap: 8px !important;
    `;
    toast.innerHTML = '🛡️ PromptShield: Restored original credentials on clipboard!';
    document.body.appendChild(toast);
    setTimeout(() => { if (toast) toast.remove(); }, 3500);
  }

  console.log("🛡️ PromptShield v1.3.0: Active with MutationObserver + Round-Trip Copy Hook.");
})();

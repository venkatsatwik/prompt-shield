/**
 * PromptShield - In-Page Content Script (Enhanced Universal Hook)
 * Intercepts AI prompt boxes, detects credentials, performs round-trip masking,
 * and restores real values when copying responses.
 */

(function () {
  console.log("🛡️ PromptShield: Initializing content script on", window.location.hostname);

  const detector = new SecretDetector();
  const masker = new SecretMasker();

  let activeAlertCard = null;
  let lastScannedText = '';
  let pendingScanResult = null;
  let currentTargetEl = null;

  const host = window.location.hostname;
  const platformName = host.includes('chatgpt') ? 'ChatGPT' :
                       host.includes('claude') ? 'Claude' :
                       host.includes('gemini') ? 'Gemini' :
                       host.includes('deepseek') ? 'DeepSeek' : 'GenAI';

  /**
   * Universal text getter for both textarea and contenteditable divs (ProseMirror / Lexical)
   */
  function getTextFromElement(el) {
    if (!el) return '';
    if (el.value !== undefined) {
      return el.value;
    }
    return el.innerText || el.textContent || '';
  }

  /**
   * Universal text setter
   */
  function setTextToElement(el, text) {
    if (!el) return;
    if (el.value !== undefined) {
      el.value = text;
    } else {
      // For contenteditable / ProseMirror on ChatGPT & Claude
      el.innerText = text;
    }

    // Dispatch standard React / Vue input events
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text }));
  }

  /**
   * Finds the active prompt element or closest input parent
   */
  function resolveInputTarget(target) {
    if (!target) return null;
    return target.closest('#prompt-textarea, [contenteditable="true"], textarea, rich-textarea textarea') ||
           document.querySelector('#prompt-textarea') ||
           document.querySelector('[contenteditable="true"]') ||
           document.querySelector('textarea');
  }

  /**
   * Log anonymized audit event to chrome.storage.local
   */
  function logAuditEvent(sanitizedCount, secretTypes) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['auditLogs', 'stats'], (result) => {
        const logs = result.auditLogs || [];
        const stats = result.stats || { totalBlocked: 0, platformCounts: {} };

        logs.unshift({
          id: Date.now(),
          timestamp: new Date().toISOString(),
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

  /**
   * Shows the PromptShield Floating Alert Card
   */
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
          <span>🎭 Sanitize & Auto-Mask</span>
        </button>
      </div>
    `;

    document.body.appendChild(card);
    activeAlertCard = card;

    // Position directly above the prompt box
    positionAlert(inputEl, card);

    // Button: Sanitize & Auto-Mask
    card.querySelector('#ps-btn-sanitize').addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();

      const rawText = getTextFromElement(inputEl);
      const masked = masker.mask(rawText, scanResult.secrets);
      setTextToElement(inputEl, masked.sanitizedText);

      const secretTypes = [...new Set(scanResult.secrets.map(s => s.category))];
      logAuditEvent(scanResult.totalFound, secretTypes);

      removeAlert();
      lastScannedText = masked.sanitizedText;
    });

    // Button: Dismiss
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
    
    // Position card floating above the prompt area
    const cardHeight = card.offsetHeight || 120;
    const topPos = Math.max(10, rect.top - cardHeight - 14);
    const leftPos = Math.max(16, rect.left);
    const width = Math.min(rect.width, 700);

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

  /**
   * Main scan function
   */
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
      console.log("🛡️ PromptShield: Secrets detected!", result.secrets);
      pendingScanResult = result;
      showAlert(inputEl, result);
    } else {
      pendingScanResult = null;
      removeAlert();
    }
  }

  // Window resize: re-position if active
  window.addEventListener('resize', () => {
    if (activeAlertCard && currentTargetEl) {
      positionAlert(currentTargetEl, activeAlertCard);
    }
  });

  // Event 1: Typing
  document.addEventListener('input', (e) => {
    const inputEl = resolveInputTarget(e.target);
    if (inputEl) {
      checkText(inputEl);
    }
  }, true);

  // Event 2: Paste (crucial 50ms delay for contenteditable)
  document.addEventListener('paste', (e) => {
    const inputEl = resolveInputTarget(e.target);
    setTimeout(() => {
      const activeEl = inputEl || resolveInputTarget(document.activeElement);
      if (activeEl) {
        checkText(activeEl);
      }
    }, 60);
  }, true);

  // Event 3: Enter Key interception
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

  // Event 4: Round-Trip Copy Restoration
  document.addEventListener('copy', (e) => {
    const selectedText = window.getSelection().toString();
    if (!selectedText) return;

    if (masker.vault.size > 0 && selectedText.includes('<')) {
      const restored = masker.restore(selectedText);
      if (restored !== selectedText) {
        e.clipboardData.setData('text/plain', restored);
        e.preventDefault();
        showCopyToast();
      }
    }
  });

  function showCopyToast() {
    const toast = document.createElement('div');
    toast.style.cssText = `
      position: fixed; bottom: 24px; right: 24px; z-index: 2147483647;
      background: #10b981; color: white; padding: 10px 18px; border-radius: 8px;
      font-size: 13px; font-weight: 600; font-family: sans-serif;
      box-shadow: 0 10px 25px rgba(0,0,0,0.4); display: flex; align-items: center; gap: 8px;
    `;
    toast.innerHTML = '🛡️ PromptShield: Restored original credentials on clipboard!';
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2500);
  }

  console.log("🛡️ PromptShield: Hook attached successfully.");
})();

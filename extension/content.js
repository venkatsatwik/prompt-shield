/**
 * PromptShield - In-Page Content Script
 * Intercepts AI prompt boxes, detects credentials, performs round-trip masking,
 * and restores real values when copying responses.
 */

(function () {
  const detector = new SecretDetector();
  const masker = new SecretMasker();

  let activeAlertCard = null;
  let lastScannedText = '';
  let pendingScanResult = null;

  // Platform Detection
  const host = window.location.hostname;
  const platformName = host.includes('chatgpt') ? 'ChatGPT' :
                       host.includes('claude') ? 'Claude' :
                       host.includes('gemini') ? 'Gemini' :
                       host.includes('deepseek') ? 'DeepSeek' : 'GenAI';

  /**
   * Finds the primary prompt input element on the current AI platform
   */
  function findPromptInput() {
    return (
      document.querySelector('#prompt-textarea') ||                          // ChatGPT
      document.querySelector('div[contenteditable="true"][role="textbox"]') || // Claude / ChatGPT
      document.querySelector('div[contenteditable="true"]') ||                 // Generic
      document.querySelector('rich-textarea textarea') ||                     // Gemini
      document.querySelector('textarea')                                       // Fallback
    );
  }

  function getPromptText(inputEl) {
    if (!inputEl) return '';
    return inputEl.value !== undefined ? inputEl.value : inputEl.innerText;
  }

  function setPromptText(inputEl, text) {
    if (!inputEl) return;
    if (inputEl.value !== undefined) {
      inputEl.value = text;
    } else {
      inputEl.innerText = text;
    }
    // Dispatch input events so React/Vue state updates
    inputEl.dispatchEvent(new Event('input', { bubbles: true }));
    inputEl.dispatchEvent(new Event('change', { bubbles: true }));
  }

  /**
   * Log anonymized audit event to local storage
   */
  function logAuditEvent(sanitizedCount, secretTypes) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['auditLogs', 'stats'], (result) => {
        const logs = result.auditLogs || [];
        const stats = result.stats || { totalBlocked: 0, platformCounts: {} };

        // Append audit log
        logs.unshift({
          id: Date.now(),
          timestamp: new Date().toISOString(),
          platform: platformName,
          secretsCount: sanitizedCount,
          categories: secretTypes
        });

        // Cap logs at 100 entries
        if (logs.length > 100) logs.pop();

        // Update stats
        stats.totalBlocked += sanitizedCount;
        stats.platformCounts[platformName] = (stats.platformCounts[platformName] || 0) + sanitizedCount;

        chrome.storage.local.set({ auditLogs: logs, stats: stats });
      });
    }
  }

  /**
   * Creates and displays the inline warning banner
   */
  function showAlert(inputEl, scanResult) {
    removeAlert();

    const container = inputEl.closest('form') || inputEl.parentElement;
    if (!container) return;

    if (getComputedStyle(container).position === 'static') {
      container.style.position = 'relative';
    }

    const card = document.createElement('div');
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
          PromptShield: Credentials Detected
        </div>
        <span class="promptshield-badge-count">${scanResult.totalFound} Secret${scanResult.totalFound > 1 ? 's' : ''}</span>
      </div>
      <div class="promptshield-body">
        This prompt contains sensitive credentials that will be exposed to ${platformName}.
        <div class="promptshield-secret-tags">${tagsHtml}</div>
      </div>
      <div class="promptshield-actions">
        <button class="promptshield-btn-dismiss" id="ps-btn-dismiss">Edit Manually</button>
        <button class="promptshield-btn-sanitize" id="ps-btn-sanitize">
          <span>🎭 Sanitize & Auto-Mask</span>
        </button>
      </div>
    `;

    container.appendChild(card);
    activeAlertCard = card;
    inputEl.classList.add('promptshield-danger-glow');

    // Attach button handlers
    card.querySelector('#ps-btn-sanitize').addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();

      const rawText = getPromptText(inputEl);
      const masked = masker.mask(rawText, scanResult.secrets);
      setPromptText(inputEl, masked.sanitizedText);

      const secretTypes = [...new Set(scanResult.secrets.map(s => s.category))];
      logAuditEvent(scanResult.totalFound, secretTypes);

      removeAlert(inputEl);
      lastScannedText = masked.sanitizedText;
    });

    card.querySelector('#ps-btn-dismiss').addEventListener('click', (e) => {
      e.preventDefault();
      removeAlert(inputEl);
    });
  }

  function removeAlert(inputEl) {
    if (activeAlertCard) {
      activeAlertCard.remove();
      activeAlertCard = null;
    }
    const target = inputEl || findPromptInput();
    if (target) {
      target.classList.remove('promptshield-danger-glow');
    }
  }

  /**
   * Scans input text on user typing or pasting
   */
  function handleInput(e) {
    const inputEl = e.target;
    const text = getPromptText(inputEl);

    if (text === lastScannedText) return;
    lastScannedText = text;

    const result = detector.scan(text);
    if (result.detected) {
      pendingScanResult = result;
      showAlert(inputEl, result);
    } else {
      pendingScanResult = null;
      removeAlert(inputEl);
    }
  }

  /**
   * Intercept Enter key to prevent accidental submission while unmasked
   */
  function handleKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey && pendingScanResult && pendingScanResult.detected) {
      e.preventDefault();
      e.stopPropagation();
      // Highlight the alert
      if (activeAlertCard) {
        activeAlertCard.style.transform = 'scale(1.02)';
        setTimeout(() => {
          if (activeAlertCard) activeAlertCard.style.transform = 'scale(1)';
        }, 150);
      }
    }
  }

  /**
   * Round-Trip Restoration Hook:
   * When user copies code or text generated by the AI,
   * restore tokens (<AWS_KEY_1>) back to original secrets locally on clipboard!
   */
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
      position: fixed; bottom: 24px; right: 24px; z-index: 99999999;
      background: #10b981; color: white; padding: 10px 18px; border-radius: 8px;
      font-size: 13px; font-weight: 600; font-family: sans-serif;
      box-shadow: 0 10px 25px rgba(0,0,0,0.4); display: flex; align-items: center; gap: 8px;
    `;
    toast.innerHTML = '🛡️ PromptShield: Restored original credentials on clipboard!';
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2500);
  }

  // Bind Listeners
  document.addEventListener('input', (e) => {
    const input = findPromptInput();
    if (e.target === input || input?.contains(e.target)) {
      handleInput(e);
    }
  }, true);

  document.addEventListener('keydown', (e) => {
    const input = findPromptInput();
    if (e.target === input || input?.contains(e.target)) {
      handleKeyDown(e);
    }
  }, true);

  console.log(`🛡️ PromptShield active on ${platformName} (Zero-Knowledge DLP)`);
})();

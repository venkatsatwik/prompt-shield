document.addEventListener('DOMContentLoaded', () => {
  const detector = new SecretDetector();
  const masker = new SecretMasker();

  const promptInput = document.getElementById('prompt-input');
  const detectionBanner = document.getElementById('detection-banner');
  const bannerCount = document.getElementById('banner-count');
  const detectedTags = document.getElementById('detected-tags');
  const btnSanitize = document.getElementById('btn-sanitize');
  const sanitizedPreview = document.getElementById('sanitized-preview');
  const aiResponsePreview = document.getElementById('ai-response-preview');
  const btnCopyAi = document.getElementById('btn-copy-ai');
  const clipboardToast = document.getElementById('clipboard-toast');
  const metricBlocked = document.getElementById('metric-blocked');
  const auditLogList = document.getElementById('audit-log-list');
  const btnClearLogs = document.getElementById('btn-clear-logs');
  const statusIndicator = document.querySelector('.status-indicator');

  let currentScanResult = null;
  let blockedCount = 0;
  let isExtensionConnected = false;

  // ========================================================
  // REAL-TIME EXTENSION SYNC BRIDGE
  // ========================================================
  window.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'PROMPTSHIELD_SYNC') {
      isExtensionConnected = true;
      const stats = event.data.stats || { totalBlocked: 0 };
      const auditLogs = event.data.auditLogs || [];

      // Update Header Indicator
      if (statusIndicator) {
        statusIndicator.innerHTML = `
          <span class="pulse-dot"></span>
          <span>🟢 Extension Connected & Live Synced</span>
        `;
        statusIndicator.style.background = 'rgba(16, 185, 129, 0.15)';
        statusIndicator.style.borderColor = 'rgba(16, 185, 129, 0.4)';
      }

      // Update Metrics from real Chrome Extension storage
      blockedCount = stats.totalBlocked;
      metricBlocked.innerText = blockedCount;

      // Render Real Historical Audit Logs
      if (auditLogs.length > 0) {
        auditLogList.innerHTML = '';
        auditLogs.forEach(log => {
          const entry = document.createElement('div');
          entry.className = 'log-entry';
          entry.innerHTML = `
            <span>${log.timestamp || 'Recent'} - [${log.platform}] Masked ${log.secretsCount} secret(s)</span>
            <span class="text-green">[Secure]</span>
          `;
          auditLogList.appendChild(entry);
        });
      }
      console.log("🛡️ PromptShield Web: Synced live stats from Chrome Extension!", stats);
    }
  });

  // Ping the extension on load
  window.postMessage({ type: 'PROMPTSHIELD_PING' }, '*');
  setTimeout(() => window.postMessage({ type: 'PROMPTSHIELD_PING' }, '*'), 500);

  // ========================================================
  // INTERACTIVE LIVE PLAYGROUND
  // ========================================================
  const templates = {
    aws: `// Connecting AWS S3 Client\nconst s3 = new AWS.S3({\n  accessKeyId: "AKIAIOSFODNN7EXAMPLE",\n  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n  region: "us-east-1"\n});`,
    db: `// Database Setup Script\nconst connectionString = "postgres://postgres_admin:SuperSecretPass992!@prod-db.us-west-2.rds.amazonaws.com:5432/customer_production";\nconst client = new Client({ connectionString });`,
    tokens: `// GitHub and OpenAI API Sync\nconst GITHUB_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";\nconst OPENAI_KEY = "sk-proj-abc1234567890abcdef1234567890abcdef12";\nconsole.log("Tokens loaded");`,
    cc: `// Customer Billing Mock Data\nconst testCard = {\n  holder: "John Doe",\n  number: "4532 0150 1234 5674",\n  exp: "12/28"\n};`
  };

  document.querySelectorAll('.pill-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.getAttribute('data-template');
      if (templates[type]) {
        promptInput.value = templates[type];
        runScan();
      }
    });
  });

  promptInput.addEventListener('input', runScan);

  function runScan() {
    const text = promptInput.value;
    if (!text.trim()) {
      detectionBanner.classList.add('hidden');
      sanitizedPreview.innerText = '// Sanitized text will appear here...';
      aiResponsePreview.innerText = '// AI response containing <TOKENS> will appear here...';
      currentScanResult = null;
      return;
    }

    currentScanResult = detector.scan(text);

    if (currentScanResult.detected) {
      detectionBanner.classList.remove('hidden');
      bannerCount.innerText = `⚠️ ${currentScanResult.totalFound} Secret${currentScanResult.totalFound > 1 ? 's' : ''} Detected`;

      detectedTags.innerHTML = currentScanResult.secrets
        .map(s => `<span class="tag">${s.label}</span>`)
        .join('');
    } else {
      detectionBanner.classList.add('hidden');
    }
  }

  btnSanitize.addEventListener('click', () => {
    if (!currentScanResult || !currentScanResult.detected) return;

    const raw = promptInput.value;
    const masked = masker.mask(raw, currentScanResult.secrets);

    sanitizedPreview.innerText = masked.sanitizedText;
    sanitizedPreview.classList.remove('text-muted');

    const simulatedResponse = `// AI Generated Output based on your sanitized prompt:\nfunction initializeServices() {\n  console.log("Connecting using sanitized tokens...");\n  ${masked.sanitizedText.split('\n')[1] || masked.sanitizedText}\n  return { status: "initialized", safe: true };\n}`;
    aiResponsePreview.innerText = simulatedResponse;

    blockedCount += currentScanResult.totalFound;
    metricBlocked.innerText = blockedCount;

    addAuditLog(currentScanResult.secrets);
    detectionBanner.classList.add('hidden');
  });

  btnCopyAi.addEventListener('click', () => {
    const aiText = aiResponsePreview.innerText;
    if (!aiText || aiText.startsWith('// AI response')) return;

    const restoredText = masker.restore(aiText);

    navigator.clipboard.writeText(restoredText).then(() => {
      clipboardToast.classList.remove('hidden');
      setTimeout(() => clipboardToast.classList.add('hidden'), 3500);
    });
  });

  function addAuditLog(secrets) {
    if (auditLogList.querySelector('.log-empty')) {
      auditLogList.innerHTML = '';
    }

    const time = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
      <span>${time} - [Playground] Masked ${secrets.length} secret(s)</span>
      <span class="text-green">[Secure]</span>
    `;
    auditLogList.prepend(entry);
  }

  btnClearLogs.addEventListener('click', () => {
    auditLogList.innerHTML = '<div class="log-empty">Audit logs cleared.</div>';
  });
});

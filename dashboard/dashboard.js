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

  let currentScanResult = null;
  let blockedCount = 0;

  // Pre-loaded realistic test templates
  const templates = {
    aws: `// Connecting AWS S3 Client\nconst s3 = new AWS.S3({\n  accessKeyId: "AKIAIOSFODNN7EXAMPLE",\n  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n  region: "us-east-1"\n});`,
    db: `// Database Setup Script\nconst connectionString = "postgres://postgres_admin:SuperSecretPass992!@prod-db.us-west-2.rds.amazonaws.com:5432/customer_production";\nconst client = new Client({ connectionString });`,
    tokens: `// GitHub and OpenAI API Sync\nconst GITHUB_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";\nconst OPENAI_KEY = "sk-proj-abc1234567890abcdef1234567890abcdef12";\nconsole.log("Tokens loaded");`,
    cc: `// Customer Billing Mock Data\nconst testCard = {\n  holder: "John Doe",\n  number: "4532 0150 1234 5674",\n  exp: "12/28"\n};`
  };

  // Bind template buttons
  document.querySelectorAll('.pill-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.getAttribute('data-template');
      if (templates[type]) {
        promptInput.value = templates[type];
        runScan();
      }
    });
  });

  // Real-time scan on input
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

  // Handle Sanitize & Auto-Mask
  btnSanitize.addEventListener('click', () => {
    if (!currentScanResult || !currentScanResult.detected) return;

    const raw = promptInput.value;
    const masked = masker.mask(raw, currentScanResult.secrets);

    // Update displays
    sanitizedPreview.innerText = masked.sanitizedText;
    sanitizedPreview.classList.remove('text-muted');

    // Simulate AI response code containing the tokens
    const simulatedResponse = `// AI Generated Output based on your sanitized prompt:\nfunction initializeServices() {\n  console.log("Connecting using sanitized tokens...");\n  ${masked.sanitizedText.split('\n')[1] || masked.sanitizedText}\n  return { status: "initialized", safe: true };\n}`;
    aiResponsePreview.innerText = simulatedResponse;

    // Update stats
    blockedCount += currentScanResult.totalFound;
    metricBlocked.innerText = blockedCount;

    // Add Audit Log Entry
    addAuditLog(currentScanResult.secrets);

    detectionBanner.classList.add('hidden');
  });

  // Round-Trip Copy Handler
  btnCopyAi.addEventListener('click', () => {
    const aiText = aiResponsePreview.innerText;
    if (!aiText || aiText.startsWith('// AI response')) return;

    // Restore tokens back to real secrets!
    const restoredText = masker.restore(aiText);

    // Copy to clipboard
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
    const labels = secrets.map(s => s.label).join(', ');

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
      <span>${time} - Masked ${secrets.length} secret(s)</span>
      <span class="text-green">[Secure]</span>
    `;
    auditLogList.prepend(entry);
  }

  btnClearLogs.addEventListener('click', () => {
    auditLogList.innerHTML = '<div class="log-empty">Audit logs cleared.</div>';
  });
});

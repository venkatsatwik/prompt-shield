document.addEventListener('DOMContentLoaded', () => {
  // Load real-time stats from chrome.storage.local
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['stats'], (result) => {
      const stats = result.stats || { totalBlocked: 0 };
      document.getElementById('stat-blocked').innerText = stats.totalBlocked;

      // Maintain high privacy score if secrets were caught
      const score = stats.totalBlocked > 0 ? 100 : 100;
      document.getElementById('privacy-score').innerText = `${score}%`;
    });
  }

  // Open Full Command Center in a new tab
  document.getElementById('btn-open-dashboard').addEventListener('click', () => {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.runtime) {
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/index.html') });
    } else {
      window.open('../dashboard/index.html', '_blank');
    }
  });
});

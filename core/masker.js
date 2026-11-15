/**
 * PromptShield - Round-Trip Secret Masker (Enhanced with HTML-Entity Support)
 */

class SecretMasker {
  constructor() {
    this.vault = new Map(); // token -> originalValue
    this.counters = {};     // prefix -> count
  }

  clearVault() {
    this.vault.clear();
    this.counters = {};
  }

  _generateToken(prefix) {
    this.counters[prefix] = (this.counters[prefix] || 0) + 1;
    return `<${prefix}_${this.counters[prefix]}>`;
  }

  mask(text, secrets) {
    if (!secrets || secrets.length === 0) {
      return { sanitizedText: text, replacements: [] };
    }

    let sanitizedText = text;
    const replacements = [];
    const sortedSecrets = [...secrets].sort((a, b) => b.start - a.start);

    for (const secret of sortedSecrets) {
      const token = this._generateToken(secret.tokenPrefix || 'SECRET');
      this.vault.set(token, secret.value);

      sanitizedText =
        sanitizedText.substring(0, secret.start) +
        token +
        sanitizedText.substring(secret.end);

      replacements.push({
        token: token,
        originalValue: secret.value,
        label: secret.label,
        category: secret.category,
        severity: secret.severity
      });
    }

    return {
      sanitizedText,
      replacements: replacements.reverse(),
      vaultSize: this.vault.size
    };
  }

  /**
   * Restores sanitized tokens in AI text (supports both raw <TOKEN> and HTML &lt;TOKEN&gt;)
   */
  restore(textWithTokens) {
    if (!textWithTokens || this.vault.size === 0) {
      return textWithTokens;
    }

    let restoredText = textWithTokens;
    for (const [token, originalVal] of this.vault.entries()) {
      // 1. Raw token: <AWS_KEY_1>
      const escapedToken = token.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
      restoredText = restoredText.replace(new RegExp(escapedToken, 'g'), originalVal);

      // 2. HTML escaped token: &lt;AWS_KEY_1&gt;
      const htmlEscapedToken = token
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
      restoredText = restoredText.replace(new RegExp(htmlEscapedToken, 'g'), originalVal);
    }
    return restoredText;
  }

  getVaultMappings() {
    const mappings = {};
    for (const [k, v] of this.vault.entries()) {
      mappings[k] = v;
    }
    return mappings;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecretMasker;
}
if (typeof window !== 'undefined') {
  window.SecretMasker = SecretMasker;
}

/**
 * PromptShield - Round-Trip Secret Masker
 * Replaces sensitive data with clean, semantically meaningful tokens (<AWS_KEY_1>, <DB_URI_1>)
 * and restores the real values locally when copying the AI's response.
 */

class SecretMasker {
  constructor() {
    this.vault = new Map(); // token -> originalValue
    this.counters = {};     // prefix -> count
  }

  /**
   * Resets the ephemeral mapping vault
   */
  clearVault() {
    this.vault.clear();
    this.counters = {};
  }

  /**
   * Generates a clean token name: e.g. <AWS_KEY_1>, <PASSWORD_1>
   */
  _generateToken(prefix) {
    this.counters[prefix] = (this.counters[prefix] || 0) + 1;
    return `<${prefix}_${this.counters[prefix]}>`;
  }

  /**
   * Masks detected secrets in the input text and stores mapping in memory
   * @param {string} text - Original prompt
   * @param {Array} secrets - Detected secrets from SecretDetector.scan()
   * @returns {Object} { sanitizedText: string, replacements: Array }
   */
  mask(text, secrets) {
    if (!secrets || secrets.length === 0) {
      return { sanitizedText: text, replacements: [] };
    }

    let sanitizedText = text;
    const replacements = [];

    // Replace from end to start to maintain string index offsets
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
   * Restores sanitized tokens in AI-generated text back to original values
   * @param {string} textWithTokens - Text containing <TOKEN_1>
   * @returns {string} Restored text with real secrets
   */
  restore(textWithTokens) {
    if (!textWithTokens || this.vault.size === 0) {
      return textWithTokens;
    }

    let restoredText = textWithTokens;
    for (const [token, originalVal] of this.vault.entries()) {
      // Replace all occurrences of this token
      const escapedToken = token.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
      restoredText = restoredText.replace(new RegExp(escapedToken, 'g'), originalVal);
    }
    return restoredText;
  }

  /**
   * Returns current active vault mappings (for debug / inspection)
   */
  getVaultMappings() {
    const mappings = {};
    for (const [k, v] of this.vault.entries()) {
      mappings[k] = v;
    }
    return mappings;
  }
}

// Export for ES Module, CommonJS, and Browser window
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecretMasker;
}
if (typeof window !== 'undefined') {
  window.SecretMasker = SecretMasker;
}

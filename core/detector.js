/**
 * PromptShield - Multi-Engine Secret & PII Detector
 * Combines Signature Regexes, Shannon Entropy, and Algorithmic Checksums (Luhn)
 * Runs 100% locally in-memory with zero external telemetry.
 */

class SecretDetector {
  constructor() {
    this.patterns = [
      // Cloud Credentials
      {
        id: 'aws_access_key',
        label: 'AWS Access Key ID',
        category: 'cloud_keys',
        severity: 'critical',
        regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
        tokenPrefix: 'AWS_KEY'
      },
      {
        id: 'aws_secret_key',
        label: 'AWS Secret Access Key',
        category: 'cloud_keys',
        severity: 'critical',
        regex: /(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
        tokenPrefix: 'AWS_SECRET'
      },
      {
        id: 'gcp_api_key',
        label: 'Google Cloud API Key',
        category: 'cloud_keys',
        severity: 'critical',
        regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
        tokenPrefix: 'GCP_KEY'
      },

      // Developer & Platform Tokens
      {
        id: 'github_token',
        label: 'GitHub Personal Access Token',
        category: 'dev_tokens',
        severity: 'critical',
        regex: /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})\b/g,
        tokenPrefix: 'GITHUB_TOKEN'
      },
      {
        id: 'openai_key',
        label: 'OpenAI API Secret Key',
        category: 'dev_tokens',
        severity: 'high',
        regex: /\bsk-[A-Za-z0-9_-]{32,}\b/g,
        tokenPrefix: 'OPENAI_KEY'
      },
      {
        id: 'anthropic_key',
        label: 'Anthropic Claude API Key',
        category: 'dev_tokens',
        severity: 'high',
        regex: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g,
        tokenPrefix: 'ANTHROPIC_KEY'
      },
      {
        id: 'slack_webhook',
        label: 'Slack Webhook URL',
        category: 'dev_tokens',
        severity: 'high',
        regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9A-Za-z]{24}/g,
        tokenPrefix: 'SLACK_WEBHOOK'
      },

      // Databases & Infrastructure
      {
        id: 'db_connection_url',
        label: 'Database Connection URI with Password',
        category: 'database',
        severity: 'critical',
        regex: /\b(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis):\/\/[a-zA-Z0-9_]+:([^@\s]+)@[a-zA-Z0-9.-]+(?::[0-9]+)?\/[a-zA-Z0-9_.-]+/g,
        tokenPrefix: 'DB_URI'
      },
      {
        id: 'private_key',
        label: 'Private Cryptographic Key',
        category: 'keys',
        severity: 'critical',
        regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[a-zA-Z0-9+/\r\n=]+-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
        tokenPrefix: 'PRIVATE_KEY'
      },
      {
        id: 'jwt_token',
        label: 'JSON Web Token (JWT)',
        category: 'dev_tokens',
        severity: 'medium',
        regex: /\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/g,
        tokenPrefix: 'JWT_TOKEN'
      },

      // Generic Credentials & Password Assignments
      {
        id: 'password_assignment',
        label: 'Password Assignment',
        category: 'passwords',
        severity: 'high',
        regex: /(?:password|passwd|pwd|db_pass|api_secret)\s*[:=]\s*['"]([^'"\r\n]{4,})['"]/gi,
        tokenPrefix: 'PASSWORD'
      }
    ];

    // High-entropy token threshold
    this.entropyThreshold = 4.3;
    this.minEntropyLength = 16;
  }

  /**
   * Calculates Shannon Entropy of a string: H(X) = -sum(P(x) * log2(P(x)))
   */
  calculateShannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const len = str.length;
    const frequencies = {};

    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Luhn Algorithm Checksum for Credit Card Validation
   */
  isValidLuhn(cardNumber) {
    const cleaned = cardNumber.replace(/\D/g, '');
    if (cleaned.length < 13 || cleaned.length > 19) return false;

    let sum = 0;
    let shouldDouble = false;

    for (let i = cleaned.length - 1; i >= 0; i--) {
      let digit = parseInt(cleaned.charAt(i), 10);
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
  }

  /**
   * Primary Scan Method
   * @param {string} text - User prompt to scan
   * @returns {Object} { detected: boolean, totalFound: number, secrets: [] }
   */
  scan(text) {
    if (!text || typeof text !== 'string') {
      return { detected: false, totalFound: 0, secrets: [] };
    }

    const secrets = [];
    const matchedRanges = [];

    const isOverlapping = (start, end) => {
      return matchedRanges.some(r => (start >= r.start && start < r.end) || (end > r.start && end <= r.end));
    };

    // 1. Run Pattern Matching Engine
    for (const pattern of this.patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;

      while ((match = regex.exec(text)) !== null) {
        const fullMatch = match[0];
        // If there's a capture group (e.g. password assignment), grab group 1; otherwise full match
        const secretVal = match[1] || fullMatch;
        const startIndex = match.index + (fullMatch.indexOf(secretVal));
        const endIndex = startIndex + secretVal.length;

        if (!isOverlapping(startIndex, endIndex)) {
          matchedRanges.push({ start: startIndex, end: endIndex });
          secrets.push({
            id: pattern.id,
            label: pattern.label,
            category: pattern.category,
            severity: pattern.severity,
            value: secretVal,
            start: startIndex,
            end: endIndex,
            tokenPrefix: pattern.tokenPrefix
          });
        }
      }
    }

    // 2. Run Credit Card / Luhn Algorithm Engine
    const ccRegex = /\b(?:\d[ -]*?){13,19}\b/g;
    let ccMatch;
    while ((ccMatch = ccRegex.exec(text)) !== null) {
      const candidate = ccMatch[0].trim();
      const startIndex = ccMatch.index;
      const endIndex = startIndex + candidate.length;

      if (!isOverlapping(startIndex, endIndex) && this.isValidLuhn(candidate)) {
        matchedRanges.push({ start: startIndex, end: endIndex });
        secrets.push({
          id: 'credit_card',
          label: 'Payment Card Number (Luhn Validated)',
          category: 'financial_pii',
          severity: 'critical',
          value: candidate,
          start: startIndex,
          end: endIndex,
          tokenPrefix: 'CREDIT_CARD'
        });
      }
    }

    // 3. Run Shannon Entropy Engine (Unidentified High-Randomness Strings)
    const words = text.split(/[\s,;=()]+/);
    for (const word of words) {
      const cleanWord = word.replace(/^['"]|['"]$/g, '');
      if (cleanWord.length >= this.minEntropyLength) {
        const entropy = this.calculateShannonEntropy(cleanWord);
        // Exclude common file paths or URLs
        if (entropy >= this.entropyThreshold && !cleanWord.startsWith('http') && !cleanWord.includes('/')) {
          const startIndex = text.indexOf(cleanWord);
          const endIndex = startIndex + cleanWord.length;

          if (startIndex !== -1 && !isOverlapping(startIndex, endIndex)) {
            matchedRanges.push({ start: startIndex, end: endIndex });
            secrets.push({
              id: 'high_entropy_secret',
              label: `High-Entropy Secret Token (${entropy.toFixed(1)} bits)`,
              category: 'passwords',
              severity: 'high',
              value: cleanWord,
              start: startIndex,
              end: endIndex,
              tokenPrefix: 'SECRET_TOKEN'
            });
          }
        }
      }
    }

    return {
      detected: secrets.length > 0,
      totalFound: secrets.length,
      secrets: secrets.sort((a, b) => a.start - b.start)
    };
  }
}

// Export for ES Module, CommonJS, and Browser window
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecretDetector;
}
if (typeof window !== 'undefined') {
  window.SecretDetector = SecretDetector;
}

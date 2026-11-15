# 🛡️ PromptShield: Zero-Knowledge GenAI Data Loss Prevention (DLP)

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Manifest V3](https://img.shields.io/badge/Chrome_Extension-Manifest_V3-blue.svg)]()
[![Zero-Knowledge](https://img.shields.io/badge/Architecture-100%25_Local_(Zero_Telemetry)-brightgreen.svg)]()

> A client-side, zero-knowledge security firewall for GenAI platforms (ChatGPT, Claude, Gemini). Automatically detects, masks, and round-trip restores API keys, database credentials, and PII before they leak to external AI models.

---

## 🎯 The Problem

Developers and enterprise teams paste sensitive code into AI assistants every day. A single prompt can accidentally leak:
- **Cloud Credentials:** AWS Access Keys (`AKIA...`), GCP tokens, Azure keys.
- **Database URIs:** Production database passwords in connection strings (`postgres://admin:...`).
- **Developer Secrets:** GitHub tokens (`ghp_...`), OpenAI API keys, private SSH keys.
- **Financial & PII:** Credit card numbers and customer identifiers.

Once submitted, these secrets reside on third-party AI training servers and are vulnerable to data extraction, prompt injection, and compliance violations (GDPR, HIPAA, PCI-DSS).

---

## ⚡ The Solution: PromptShield Trifecta

PromptShield operates directly inside your browser memory with **zero external telemetry**:

```
                       HOW PROMPTSHIELD WORKS
                       
  [User Pastes Text into ChatGPT / Claude]
                    │
                    ▼
  ┌─────────────────────────────────────────────────────────┐
  │ 1. MULTI-ENGINE DETECTOR                                │
  │    ├─ Pattern Matching (25+ Cloud, Dev, & DB keys)      │
  │    ├─ Shannon Entropy (Mathematical Password Scorer)    │
  │    └─ Luhn Algorithm (Algorithmic Credit Card Validator)│
  └─────────────────────────┬───────────────────────────────┘
                            │
                     (Found Secrets?)
                     ├── NO  ──> Allow normal submit
                     │
                     └── YES ──> [Intercept & Pause Submission]
                                       │
                                       ▼
  ┌─────────────────────────────────────────────────────────┐
  │ 2. ROUND-TRIP MASKER                                    │
  │    ├─ Swaps secrets with clean semantic tokens:         │
  │    │  e.g., <AWS_KEY_1>, <DB_URI_1>, <PASSWORD_1>       │
  │    ├─ Caches mapping in local browser memory            │
  │    └─ Intercepts Copy: Restores real secrets on copy!   │
  └─────────────────────────┬───────────────────────────────┘
                            │
                            ▼
  ┌─────────────────────────────────────────────────────────┐
  │ 3. ZERO-KNOWLEDGE AUDIT & COMMAND CENTER                │
  │    ├─ 100% Local Storage (chrome.storage.local)         │
  │    ├─ Granular Platform Permission Matrix (ChatGPT/etc) │
  │    └─ Live Privacy Score & Anonymized Audit Trail       │
  └─────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

1. **Multi-Engine Secret Detection:**
   - **Signature Regexes:** Detects 25+ secret formats including AWS, GitHub, OpenAI, Anthropic, Slack, JWT, and DB strings.
   - **Shannon Entropy Engine:** Identifies high-randomness passwords without relying on known prefixes ($H(X) = -\sum P(x) \log_2 P(x)$).
   - **Luhn Algorithm Checksum:** Algorithmic validation of payment cards to prevent false positives.

2. **The "Round-Trip" Secret Masker:**
   - Auto-replaces secrets with semantically meaningful placeholders (e.g. `<AWS_KEY_1>`) before sending to the model.
   - **The Magic:** When you copy AI-generated code, PromptShield automatically restores your real credentials locally onto your clipboard!

3. **Zero-Knowledge Architecture:**
   - Does **not** communicate with any backend server.
   - All scanning and tokenization execute strictly in browser memory.
   - **0 Bytes** of telemetry leave your machine.

4. **Full Command Center & Live Playground:**
   - Granular platform policies (toggle protection per AI platform).
   - Live interactive test playground with pre-loaded vulnerability templates.

---

## 🚀 Quick Start: Run as a Chrome Extension

1. **Clone this repository:**
   ```bash
   git clone https://github.com/venkatsatwik/prompt-shield.git
   ```

2. **Load into Google Chrome / Edge / Brave:**
   - Open your browser and navigate to `chrome://extensions`.
   - Toggle on **"Developer mode"** in the top-right corner.
   - Click **"Load unpacked"** in the top-left corner.
   - Select the `prompt-shield` folder.

3. **Test It Live:**
   - Open [chatgpt.com](https://chatgpt.com) or [claude.ai](https://claude.ai).
   - Try typing or pasting: `const key = "AKIAIOSFODNN7EXAMPLE";`
   - Watch the PromptShield security shield intercept it!

---

## 🌐 Deploy to Vercel (1-Click Web Playground)

This repository includes a standalone web app version of the Command Center and Interactive Playground.

1. Go to [Vercel](https://vercel.com).
2. Click **Add New Project** and select your `prompt-shield` repository.
3. Click **Deploy** (zero configuration needed).
4. Share your live link (e.g. `https://prompt-shield.vercel.app`) on your portfolio and resume!

---

## 👨‍💻 Author

- **Venkat Satwik**
- GitHub: [@venkatsatwik](https://github.com/venkatsatwik)

---

## 📄 License
This project is licensed under the MIT License.

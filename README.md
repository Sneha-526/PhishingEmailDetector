# 🛡️ Phishing Email Detector

A client-side web application that analyzes pasted email text and classifies it by phishing risk level using rule-based heuristics — no backend or external APIs required.

## 🚀 Features

- **Risk Classification**: Instantly categorizes emails as **Safe**, **Suspicious**, or **Phishing**
- **Rule-Based Analysis**: Scans for common phishing indicators including:
  - Urgency / threatening language
  - Suspicious URLs and mismatched domains
  - Requests for sensitive information (passwords, SSN, credit card)
  - Grammar anomalies and spoofed sender patterns
- **Actionable Recommendations**: Provides cybersecurity guidance based on detected risk level
- **Fully Client-Side**: Runs entirely in the browser — no data leaves your machine

## 🛠️ Tech Stack

- HTML5
- Vanilla CSS3 (dark mode, glassmorphism, animations)
- Vanilla JavaScript (no frameworks, no dependencies)

## 📂 Project Structure

```
PhishingEmailDetector/
├── index.html   # App structure and markup
├── style.css    # Styling, animations, and responsive layout
└── script.js    # Detection engine and UI logic
```

## 🏃 Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/PhishingEmailDetector.git
   ```
2. Open `index.html` in any modern web browser.
3. Paste an email into the text area and click **Analyze**.

## 📄 License

MIT

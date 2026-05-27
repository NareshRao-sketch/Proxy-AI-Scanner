<img width="1600" height="900" alt="image" src="https://github.com/user-attachments/assets/9bda6e36-b8da-42ba-b271-e2b58d436d69" /><img width="1600" height="900" alt="image" src="https://github.com/user-attachments/assets/b863e241-34f8-49c7-af98-561ddad1d925" /># proxy-ai-scanner

A desktop HTTP proxy tool that captures web traffic and lets you manually send any request to a local AI (Ollama) for security vulnerability analysis.

Built with Python and PyQt6. Inspired by Burp Suite.

---

## What It Does

- Runs a local HTTP proxy on `127.0.0.1:8080`
- Captures every request your browser makes and shows them in a table
- You pick which request to analyze — right-click → **Send to Ollama**
- Ollama (running locally on your machine) checks it for OWASP Top 10 vulnerabilities and streams the findings back

> Ollama is only called when **you** manually choose to send a request. Nothing is sent automatically.

---

## Screenshots



---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) installed and running locally
- A pulled Ollama model (e.g. `llama3`)

---

## Setup

**1. Clone the repo**
```
git clone https://github.com/YOUR-GITHUB-USERNAME/proxy-ai-scanner.git
cd proxy-ai-scanner
```

**2. Install Python dependencies**
```
pip install -r requirements.txt
```

**3. Install and start Ollama**

Download from https://ollama.com, then run:
```
ollama serve
ollama pull llama3
```

**4. Run the tool**
```
python proxy_ai_scanner.py
```

---

## How to Use

1. Run the tool — a GUI window opens
2. Click **Start Proxy** — proxy starts on `127.0.0.1:8080`
3. Set your browser proxy to `127.0.0.1:8080`
4. Browse any website — requests appear in the table
5. Click a row to preview the request and response
6. **Right-click → Send to Ollama** to analyze it
7. Click **Send to Ollama** button — findings stream into the panel below

---

## Settings

Click the **Settings** button to change:
- Ollama URL (default: `http://localhost:11434`)
- Model name (default: `llama3`)
- Timeout in seconds

---

## Vulnerabilities Checked

- SQL injection / Command injection
- Broken authentication / Weak session tokens
- Sensitive data exposure (API keys, tokens in responses)
- Missing security headers (CSP, HSTS, X-Frame-Options)
- IDOR (predictable IDs in URLs)
- CORS misconfiguration
- Information disclosure (stack traces, server versions)
- Input validation issues

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| GUI | PyQt6 |
| Proxy | mitmproxy |
| AI | Ollama (local LLM) |
| Language | Python 3 |

---

## Disclaimer

This tool is for **authorized security testing and educational use only.**  
Do not use it against systems you do not have permission to test.

---

## Author

Naresh Rao H — [HackerOne](https://hackerone.com/YOUR-H1-USERNAME) · [LinkedIn](https://linkedin.com/in/YOUR-LINKEDIN-ID)

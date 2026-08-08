# AI-Security-Auditor
# 🛡️ OWASP LLM Top 10 Automated Security Gateway & Audit Tool

An open-source, API-agnostic security gateway and automated evaluation dashboard designed to detect and mitigate the **OWASP Top 10 LLM Vulnerabilities (2025/2026)** in real-time.

![OWASP Security Dashboard](docs/YOUR_IMAGE_NAME.png)

## 🌟 Key Features
- **In-Line Pre-Execution Guardrails:** Intercepts and blocks **Direct Prompt Injections (LLM01)** before reaching the model inference layer.
- **Outbound Data Leak Protection:** Scans model outputs for **Sensitive Data & API Key Disclosures (LLM02)** and redacts credentials dynamically.
- **Automated OWASP LLM01–LLM10 Test Suite:** Runs a 10-point vulnerability battery against local (Ollama/vLLM) or cloud endpoints (OpenAI/Anthropic).
- **Asynchronous Architecture:** Built on FastAPI & `httpx` for minimal proxy latency overhead.

## 🏗️ System Architecture

[ Client / User UI ] ──► [ Security Gateway (FastAPI) ] ──► [ Target LLM ]
                             │                                  ├─ Local: Ollama / AnythingLLM
                             ├─ 1. Input Guardrails (LLM01)      └─ Cloud: OpenAI / Claude
                             └─ 2. Output Scanners (LLM02/05/07)

## 🚀 Quickstart (Local Deployment)

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/your-username/OWASP-LLM-Guardrail-Proxy.git](https://github.com/your-username/OWASP-LLM-Guardrail-Proxy.git)
   cd OWASP-LLM-Guardrail-Proxy

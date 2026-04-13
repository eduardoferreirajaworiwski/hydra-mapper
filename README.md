# Hydra-Mapper

Hydra-Mapper is a high-performance modular tool designed for real-time mapping of adversary infrastructure. It leverages CertStream to monitor SSL/TLS certificate transparency logs, identifying and collecting forensic evidence for suspicious domains in real-time.

## Key Features
- **Real-Time Monitoring:** Connects to CertStream for immediate domain identification.
- **Active Reconnaissance:** Automated identification of phishing infrastructure.
- **Digital Forensics:** (Pending) Headless evidence collection using Playwright with SHA-256 Chain of Custody.
- **Modular Structure:** Built with `core/`, `forensics/`, and `reports/` for scalability.

## Quick Start
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Setup environment variables:
   ```bash
   cp .env.example .env
   ```
3. Run the monitor:
   ```bash
   python core/monitor.py
   ```

## Governance
See [gemini_rules.md](gemini_rules.md) for project standards and forensic requirements.

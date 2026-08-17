# 🛡️ CloudSec-Guard

### *Proactive Infrastructure Security Auditor for DevSecOps*

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-CIS_Benchmarks-red.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

---

## 🚀 Why CloudSec-Guard?

Most security tools scan **after** the damage is done. **CloudSec-Guard** enables **Shift-Left Security** by auditing your infrastructure configs directly in your terminal, preventing vulnerabilities before they even reach a CI/CD pipeline.

> "Don't just scan misconfigurations—**remediate** them with AI."

---

## ✨ Core Features

### 🔍 Static Security Analysis
*   **Docker Hardening:** Detects root execution, latest tags, and uncleaned package caches.
*   **Kubernetes Auditing:** Flags privileged containers, missing resource limits, and insecure runAsNonRoot policies.

### 🤖 AI-Driven Remediation
Powered by **Google Gemini AI**. When a vulnerability is found, the tool provides:
*   A concise **security impact analysis**.
*   A **corrected, production-ready code snippet** on the spot.

### 🛡️ Security-First Architecture
*   **Path Traversal Protection:** Locked down against malicious file access (LFI).
*   **Safe Parsing:** Protects against YAML Object Injection.
*   **Audit-Ready:** Centralized logging for every scan event.

CloudSec-Guard 🛡️
Infrastructure Security Auditor | Shift-Left DevSecOps Tool

CloudSec-Guard is a production-grade CLI security auditor designed to secure your Infrastructure-as-Code (IaC) before it reaches deployment. It performs deep static analysis on Dockerfiles and Kubernetes manifests to detect misconfigurations, audit security posture, and remediate vulnerabilities on the fly using Google Gemini AI.

🚀 Why CloudSec-Guard?
Modern cloud security happens too late. CloudSec-Guard enables Shift-Left Security by auditing your infrastructure configs directly in your terminal, preventing vulnerabilities like root privilege escalation, container escapes, and node resource exhaustion before they cause production incidents.

🔑 Key Features
Static Analysis Engine: Audits Dockerfile and K8s YAML against CIS Benchmarks.

AI-Powered Remediation: Contextual vulnerability fixing using Google Gemini AI.

Security by Design:

Path Traversal Protection (LFI Prevention).

Secure YAML Deserialization (Prevents Injection).

Centralized Audit Trail (Production-grade Logging).

Modern CLI: Built with Typer & Rich for a fast, colorful, and interactive user experience.

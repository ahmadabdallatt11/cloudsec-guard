from typing import Any, Dict, List

class K8sAnalyzer:
    """
    Static security analyzer for parsed Kubernetes YAML manifests.
    Evaluates Pods and Deployments against CIS Kubernetes Benchmarks.
    """

    @staticmethod
    def analyze(documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        
        if isinstance(documents, dict):
            documents = [documents]
            
        for doc_idx, doc in enumerate(documents):
            if not doc or not isinstance(doc, dict):
                continue
                
            kind = doc.get("kind", "")
            metadata = doc.get("metadata", {})
            name = metadata.get("name", f"Document-{doc_idx}")
            spec = doc.get("spec", {})
            
            if kind in ["Deployment", "DaemonSet", "StatefulSet", "Job"]:
                pod_spec = spec.get("template", {}).get("spec", {})
            elif kind == "Pod":
                pod_spec = spec
            else:
                continue 

            containers = pod_spec.get("containers", [])
            
            for container in containers:
                c_name = container.get("name", "unknown")
                security_context = container.get("securityContext", {})
                
                # Rule 1: Privileged Container (CIS 5.2.1)
                if security_context.get("privileged") is True:
                    findings.append({
                        "id": "CSG-K8S-001",
                        "title": "Privileged Container Detected",
                        "severity": "HIGH",
                        "line": "N/A",
                        "description": f"Container '{c_name}' in {kind} '{name}' is running as privileged. This allows near-host-level access.",
                        "remediation": "Set 'securityContext.privileged: false' or remove the privileged flag."
                    })
                    
                # Rule 2: Root Container Execution (CIS 5.2.6)
                if security_context.get("runAsNonRoot") is not True:
                    findings.append({
                        "id": "CSG-K8S-002",
                        "title": "Container May Run As Root",
                        "severity": "MEDIUM",
                        "line": "N/A",
                        "description": f"Container '{c_name}' in {kind} '{name}' does not enforce runAsNonRoot. It might run as root by default.",
                        "remediation": "Set 'securityContext.runAsNonRoot: true' to enforce non-root execution."
                    })
                    
                # Rule 3: Missing Resource Limits (DoS protection)
                resources = container.get("resources", {})
                if not resources.get("limits"):
                    findings.append({
                        "id": "CSG-K8S-003",
                        "title": "Missing Resource Limits",
                        "severity": "LOW",
                        "line": "N/A",
                        "description": f"Container '{c_name}' in {kind} '{name}' has no CPU or Memory limits defined, risking Node resource exhaustion.",
                        "remediation": "Define 'resources.limits.cpu' and 'resources.limits.memory' for the container."
                    })

        return findings
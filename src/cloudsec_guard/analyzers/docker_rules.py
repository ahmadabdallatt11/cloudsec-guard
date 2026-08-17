from typing import Any, Dict, List

class DockerAnalyzer:
    """
    Static security analyzer for parsed Dockerfiles.
    Evaluates instructions against industry security benchmarks (CIS Benchmarks).
    """

    @staticmethod
    def analyze(instructions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        has_user_instruction = False
        last_user = "root"

        for item in instructions:
            instruction = item.get("instruction", "").upper()
            value = item.get("value", "").strip()
            line = item.get("line", 0)

            # Rule 1: Avoid using 'latest' or untagged base images (CIS Docker 4.1)
            if instruction == "FROM":
                if ":" not in value or value.endswith(":latest"):
                    findings.append({
                        "id": "CSG-DOCKER-001",
                        "title": "Use of 'latest' Tag in Base Image",
                        "severity": "MEDIUM",
                        "line": line,
                        "description": f"Base image '{value}' uses 'latest' or has no pinned tag. This compromises build immutability and predictability.",
                        "remediation": "Pin the base image to a specific immutable version/digest (e.g., 'ubuntu:22.04' or SHA256 digest)."
                    })

            # Rule 2: Insecure Package Manager Usage (Missing cache cleanup)
            elif instruction == "RUN":
                if "apt-get install" in value and "rm -rf /var/lib/apt/lists/*" not in value:
                    findings.append({
                        "id": "CSG-DOCKER-002",
                        "title": "Uncleaned Package Manager Cache",
                        "severity": "LOW",
                        "line": line,
                        "description": "Package manager installed dependencies without removing cache lists, increasing image attack surface and size.",
                        "remediation": "Append '&& rm -rf /var/lib/apt/lists/*' at the end of the RUN apt-get command."
                    })

            # Rule 3: Track USER configuration (CIS Docker 4.1)
            elif instruction == "USER":
                has_user_instruction = True
                last_user = value.lower()

        # Rule 4: Verify Container Non-Root Execution
        if not has_user_instruction or last_user in ["root", "0"]:
            findings.append({
                "id": "CSG-DOCKER-003",
                "title": "Container Runs as Root User",
                "severity": "HIGH",
                "line": instructions[-1].get("line", 1) if instructions else 1,
                "description": "The Dockerfile does not switch to a non-privileged user, allowing the container to run as root by default.",
                "remediation": "Define a dedicated non-root user using 'USER <username_or_uid>' before runtime instructions."
            })

        return findings
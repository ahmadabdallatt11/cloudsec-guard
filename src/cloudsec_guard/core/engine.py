from typing import Any, Dict, List, Optional
from cloudsec_guard.parsers.docker_parser import parse_dockerfile_securely
from cloudsec_guard.parsers.yaml_parser import parse_yaml_securely
from cloudsec_guard.analyzers.docker_rules import DockerAnalyzer
from cloudsec_guard.analyzers.k8s_rules import K8sAnalyzer
from cloudsec_guard.utils.logger import logger

class SecurityEngine:
    """
    Core engine orchestrating file parsing and security analysis with full logging integration.
    """

    def run_scan(self, file_path: str, file_type: str) -> Optional[List[Dict[str, Any]]]:
        logger.info(f"Initiating security scan for target: '{file_path}' [Type: {file_type}]")
        
        if file_type == "docker":
            parsed_data = parse_dockerfile_securely(file_path)
            if not parsed_data:
                logger.error(f"Failed to parse Dockerfile: '{file_path}'")
                return None
            
            logger.debug(f"Successfully parsed {len(parsed_data)} instructions from Dockerfile.")
            findings = DockerAnalyzer.analyze(parsed_data)
            logger.info(f"Docker analysis completed. Total findings: {len(findings)}")
            return findings
        
        elif file_type == "yaml":
            parsed_data = parse_yaml_securely(file_path)
            if not parsed_data:
                logger.error(f"Failed to parse YAML manifest: '{file_path}'")
                return None
            
            logger.debug("Successfully parsed YAML file structures.")
            findings = K8sAnalyzer.analyze(parsed_data)
            logger.info(f"Kubernetes analysis completed. Total findings: {len(findings)}")
            return findings

        logger.warning(f"Unsupported file type requested: '{file_type}'")
        return None
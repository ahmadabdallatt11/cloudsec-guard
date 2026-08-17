from typing import Any, Dict, List, Union
import yaml
from cloudsec_guard.utils.file_handler import read_file_securely

def parse_yaml_securely(file_path: str) -> Union[Dict[str, Any], List[Dict[str, Any]], None]:
    """
    Securely parses Kubernetes YAML manifests using safe_load_all 
    to prevent arbitrary object deserialization.
    """
    try:
        raw_content = read_file_securely(file_path)
        
        # safe_load_all handles multi-document YAML files (separated by ---)
        documents = list(yaml.safe_load_all(raw_content))
        
        # Filter out None/empty documents
        valid_docs = [doc for doc in documents if doc is not None]
        
        if not valid_docs:
            return None
            
        # If it's a single document, return it directly; otherwise return the list
        if len(valid_docs) == 1:
            return valid_docs[0]
            
        return valid_docs
        
    except yaml.YAMLError as ye:
        print(f"[PARSER ERROR] YAML syntax error in '{file_path}': {ye}")
        return None
    except Exception as e:
        print(f"[PARSER ERROR] Failed to parse YAML file '{file_path}': {e}")
        return None
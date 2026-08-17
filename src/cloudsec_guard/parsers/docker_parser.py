from typing import Any, Dict, List, Optional
from cloudsec_guard.utils.file_handler import read_file_securely

# Max characters per line to prevent CPU exhaustion/ReDoS attacks
MAX_LINE_LENGTH = 10000  

def parse_dockerfile_securely(file_path: str) -> Optional[List[Dict[str, Any]]]:
    """
    Parses a Dockerfile into a structured list of dictionaries (AST-like).
    Handles line continuations '\\' securely to prevent evasion techniques.
    
    :param file_path: The target Dockerfile path.
    :return: A list of parsed instructions or None on failure.
    """
    file_content = read_file_securely(file_path)
    if not file_content:
        return None

    instructions: List[Dict[str, Any]] = []
    current_instruction = ""
    start_line_num = 0

    lines = file_content.splitlines()
    
    for i, line in enumerate(lines):
        line_num = i + 1
        stripped_line = line.strip()

        # Ignore empty lines and standard comments
        if not stripped_line or stripped_line.startswith("#"):
            continue

        # Enforce line length limit (DoS protection)
        if len(line) > MAX_LINE_LENGTH:
            print(f"[SECURITY ALERT] Extremely long line detected at line {line_num}. Skipping to prevent DoS.")
            continue

        # If we are continuing a previous line, append to it
        if current_instruction:
            current_instruction += " " + stripped_line
        else:
            current_instruction = stripped_line
            start_line_num = line_num

        # Check if the instruction spans multiple lines
        if current_instruction.endswith("\\"):
            # Remove the trailing backslash and wait for the next iteration
            current_instruction = current_instruction[:-1].strip()
        else:
            # The line is complete, let's parse the instruction and its value
            parts = current_instruction.split(maxsplit=1)
            
            # The Docker instruction (e.g., FROM, RUN, USER, ENV)
            instruction_name = parts[0].upper()
            
            # The arguments for the instruction
            instruction_value = parts[1] if len(parts) > 1 else ""

            instructions.append({
                "instruction": instruction_name,
                "value": instruction_value,
                "line": start_line_num
            })
            
            # Reset for the next instruction
            current_instruction = ""

    if not instructions:
        print(f"[WARNING] No valid Docker instructions found in {file_path}.")
        return None

    return instructions
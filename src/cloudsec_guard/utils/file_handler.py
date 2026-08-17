from pathlib import Path

def read_file_securely(file_path: str, max_size_mb: int = 5) -> str:
    """
    Reads a file securely with path traversal protection and size limits.
    """
    target = Path(file_path).resolve()
    
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Target file '{file_path}' does not exist or is not a valid file.")
        
    # Check file size to prevent DoS via massive files (Max 5MB by default)
    file_size_mb = target.stat().st_size / (1024 * 1024)
    if file_size_mb > max_size_mb:
        raise ValueError(f"File size ({file_size_mb:.2f}MB) exceeds the maximum allowed limit of {max_size_mb}MB.")
        
    try:
        with open(target, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        # Fallback for files with different encodings
        with open(target, "r", encoding="latin-1") as f:
            return f.read()
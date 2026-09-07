"""
Notes file extractor and block segmenter.

Safely reads a plaintext credentials notes file, detecting encoding (UTF-8, UTF-16, latin1),
and segments it into lines or paragraphs for parsing.
"""

import os
from typing import List


class ExtractionError(Exception):
    """Raised when reading or segmenting the notes file fails."""
    pass


def read_notes_file(file_path: str) -> str:
    """
    Reads the contents of the notes file with robust fallback encodings.
    """
    if not os.path.exists(file_path):
        raise ExtractionError(f"Notes file does not exist: {file_path}")

    encodings = ["utf-8-sig", "utf-8", "utf-16", "cp1252", "latin-1"]
    raw = None

    with open(file_path, "rb") as f:
        raw = f.read()

    for enc in encodings:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue

    raise ExtractionError(f"Could not decode {file_path} with supported encodings.")


def segment_notes(content: str, max_chunk_chars: int = 2000) -> List[str]:
    """
    Segments raw notes into coherent text chunks suitable for LLM processing.
    Splits by blank lines or paragraphs.
    """
    lines = content.splitlines()
    chunks: List[str] = []
    current_chunk: List[str] = []
    current_length = 0

    for line in lines:
        line_len = len(line) + 1
        if current_length + line_len > max_chunk_chars and current_chunk:
            chunks.append("\n".join(current_chunk).strip())
            current_chunk = [line]
            current_length = line_len
        else:
            current_chunk.append(line)
            current_length += line_len

    if current_chunk:
        chunk_str = "\n".join(current_chunk).strip()
        if chunk_str:
            chunks.append(chunk_str)

    return chunks

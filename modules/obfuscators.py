import random
import re

def _toggle_case(s: str) -> str:
    out = []
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if random.choice([True, False]) else ch.lower())
        else:
            out.append(ch)
    return "".join(out)

def _whitespace_abuse(s: str) -> str:
    return re.sub(r"\s+", "  ", s)

def _comment_insertion(s: str) -> str:
    return s.replace("]] ", "]]/*OBF*/ ")

def apply_obfuscation(s: str, mode: str) -> str:
    if mode == "none":
        return s
    if mode == "case":
        return _toggle_case(s)
    if mode == "whitespace":
        return _whitespace_abuse(s)
    if mode == "comments":
        return _comment_insertion(s)
    if mode == "mixed":
        return _toggle_case(_comment_insertion(_whitespace_abuse(s)))
    raise ValueError("Unknown obfuscation")

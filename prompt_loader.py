"""Load editable prompts independently of the current working directory."""
import json
import os
from pathlib import Path

def load_prompts(payload):
    folder = Path(os.getenv("DEBUG_AGENT_PROMPT_DIR") or Path(__file__).parent / "prompts")
    values = []
    for name in ("system_prompt.txt", "debug_template.txt"):
        path = folder / name
        with path.open("rb") as stream:
            data = stream.read(65537)
        if len(data) > 65536:
            raise ValueError("Prompt file exceeds 64 KiB.")
        text = data.decode("utf-8-sig").strip()
        if not text:
            raise ValueError("Prompt file cannot be empty.")
        values.append(text)
    system, template = values
    if template.count("{evidence}") != 1:
        raise ValueError("debug_template.txt must contain exactly one {evidence} placeholder.")
    return system, template.replace("{evidence}", json.dumps(payload, ensure_ascii=False))

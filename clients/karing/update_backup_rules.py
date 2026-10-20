"""Add routing suffixes to an existing private backup without altering accounts.

Usage: python update_backup_rules.py INPUT.zip OUTPUT.zip DOMAINS.txt
The domain file contains one suffix per line. Never commit either backup.
"""
import io
import json
import os
from pathlib import Path
import sys
import zipfile


def update_backup(data: bytes, domains: list[str]) -> bytes:
    suffixes = {d.strip().lower().lstrip(".") for d in domains if d.strip()}
    if any("/" in d or ":" in d or " " in d or "." not in d for d in suffixes):
        raise ValueError("Expected domain suffixes, not URLs or addresses")
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(output, "w") as target:
        routing = json.loads(source.read("karing_routing_group.json"))
        matches = [g for i in routing["items"] for g in i.get("groups", [])
                   if g.get("name") == "MinBot 选择性代理"]
        if len(matches) != 1:
            raise ValueError("Expected exactly one MinBot proxy routing group")
        group = matches[0]
        group["domain_suffix"] = sorted(set(group["domain_suffix"]) | suffixes)
        for entry in source.infolist():
            body = source.read(entry.filename)
            if entry.filename == "karing_routing_group.json":
                body = json.dumps(routing, ensure_ascii=False, separators=(",", ":")).encode()
            target.writestr(entry, body)
    return output.getvalue()


if __name__ == "__main__":
    source, destination, domain_file = map(Path, sys.argv[1:])
    result = update_backup(source.read_bytes(), domain_file.read_text().splitlines())
    # Never expose embedded credentials through a world-readable new output.
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(result)

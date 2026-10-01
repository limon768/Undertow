from pathlib import Path

DIRS = [
    "dirbrute",
    "email",
    "JS",
    "Loot",
    "nmap/eyewitness/screens",
    "nmap/eyewitness/source",
    "nmap/parse/hosts",
    "subdomain/eyewitness/screens",
    "subdomain/eyewitness/source",
    "wpscan",
    "MISC",
]

FILES = ["Note.txt", "scope.txt", "web_scope.txt", "out-of-scope.txt"]


def create_engagement(name: str) -> Path:
    root = Path(name)
    for rel_dir in DIRS:
        (root / rel_dir).mkdir(parents=True, exist_ok=True)
    for filename in FILES:
        (root / filename).touch(exist_ok=True)
    return root

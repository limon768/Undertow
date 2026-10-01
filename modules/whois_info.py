import subprocess


def get_whois(domain: str) -> dict:
    try:
        result = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=15
        )
        raw = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"raw": "", "fields": {}}

    fields = {}
    wanted = {
        "registrar": "Registrar",
        "creation date": "Created",
        "registry expiry date": "Expires",
        "updated date": "Updated",
        "name server": "Name Servers",
    }
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key in wanted and value:
            label = wanted[key]
            if label == "Name Servers":
                fields.setdefault(label, [])
                if value not in fields[label]:
                    fields[label].append(value)
            elif label not in fields:
                fields[label] = value

    return {"raw": raw, "fields": fields}

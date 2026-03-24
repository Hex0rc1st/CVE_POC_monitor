allowed_advisory_severities = {"HIGH", "CRITICAL", "Unknown", "MODERATE"}


def build_advisory_search_fields(data):
    details = str(data.get('details', '') or '')
    summary = str(data.get('summary', '') or '')
    aliases = " ".join(data.get('aliases', []) or [])
    affected_names = []
    for affected in data.get('affected', []) or []:
        package = affected.get('package', {}) or {}
        package_name = package.get('name')
        if package_name:
            affected_names.append(package_name)
    for affected in data.get('vulnerabilities', []) or []:
        package = affected.get('package', {}) or {}
        package_name = package.get('name')
        if package_name:
            affected_names.append(package_name)
    return {
        "summary": summary,
        "details": details,
        "aliases": aliases,
        "affected_names": " ".join(affected_names),
    }


def extract_advisory_search_text(data):
    fields = build_advisory_search_fields(data)
    return " ".join(fields.values()).lower()


def extract_advisory_key(data, filename):
    aliases = data.get('aliases', []) or []
    if aliases:
        return aliases[0]
    return data.get('id', '') or filename


def match_known_object(data, known_object):
    search_fields = build_advisory_search_fields(data)
    normalized_fields = {key: value.lower() for key, value in search_fields.items()}
    advisory_text = " ".join(normalized_fields.values())
    severity = (data.get('database_specific', {}) or {}).get('severity', '')
    if not severity:
        severity = data.get('severity', '')
    if isinstance(severity, str):
        severity = severity.upper()
    result = {
        "matched": False,
        "severity": severity,
        "matched_object": None,
        "matched_fields": [],
        "advisory_text": advisory_text,
    }
    if severity not in allowed_advisory_severities:
        return result

    for item in known_object:
        matched_fields = [
            field_name
            for field_name, field_value in normalized_fields.items()
            if item in field_value
        ]
        if not matched_fields:
            continue
        if item == "jenkins" and "plugin" in advisory_text and "core" not in advisory_text:
            continue
        result["matched"] = True
        result["matched_object"] = item
        result["matched_fields"] = matched_fields
        return result

    return result

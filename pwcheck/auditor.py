"""Orquesta la auditoría masiva: lee el archivo, consulta cada contraseña y
arma el resultado. Cachea las respuestas por prefijo de hash (no por
contraseña) para no repetir la misma consulta de red si dos personas
eligieron la misma contraseña — algo muy común en una auditoría real."""
from __future__ import annotations

from datetime import datetime, timezone

from . import hibp, policy
from .models import AuditResult, PasswordCheck


def parse_line(line: str, line_no: int) -> tuple[str, str] | None:
    """Devuelve (etiqueta, contraseña) o None si la línea está vacía.
    Formato 'usuario:contraseña' o solo 'contraseña' (una por línea)."""
    line = line.rstrip("\n\r")
    if not line.strip():
        return None
    if ":" in line:
        label, password = line.split(":", 1)
        return label.strip() or f"línea {line_no}", password
    return f"línea {line_no}", line


def audit_file(path: str) -> AuditResult:
    result = AuditResult(checked_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    cache: dict[str, dict[str, int]] = {}

    with open(path, encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            parsed = parse_line(raw, line_no)
            if parsed is None:
                continue
            label, password = parsed
            try:
                prefix, suffix = hibp.sha1_prefix_suffix(password)
                if prefix not in cache:
                    cache[prefix] = hibp.query_range(prefix)
                count = cache[prefix].get(suffix, 0)
            except Exception as exc:  # una falla de red no debe tumbar toda la auditoría
                result.errors.append(f"{label}: no se pudo consultar ({type(exc).__name__}: {exc})")
                continue
            result.results.append(PasswordCheck(
                label=label, breach_count=count, policy_notes=policy.check_policy(password)))
    return result

"""Consulta la API pública 'Pwned Passwords' de HaveIBeenPwned usando
k-anonimato: solo se envían los primeros 5 caracteres del hash SHA-1 de la
contraseña. El servidor responde con todas las coincidencias para ese
prefijo (miles de hashes), y la comparación final para saber si coincide
EXACTAMENTE se hace en esta máquina. La contraseña, y su hash completo,
nunca viajan por la red. No requiere API key (es un endpoint público)."""
from __future__ import annotations

import hashlib

import requests

USER_AGENT = "PwCheck/0.1 (auditoria-local-de-contrasenas)"
RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
TIMEOUT = 10.0


def sha1_prefix_suffix(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def query_range(prefix: str) -> dict[str, int]:
    """Devuelve {sufijo_de_hash: veces_visto} para un prefijo de 5 caracteres."""
    resp = requests.get(
        RANGE_URL.format(prefix=prefix), timeout=TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"})
    resp.raise_for_status()
    out: dict[str, int] = {}
    for line in resp.text.splitlines():
        if ":" not in line:
            continue
        suffix, count = line.split(":", 1)
        out[suffix.strip()] = int(count.strip())
    return out


def breach_count(password: str) -> int:
    """Cuántas veces apareció esta contraseña en filtraciones conocidas (0 = ninguna)."""
    prefix, suffix = sha1_prefix_suffix(password)
    ranges = query_range(prefix)
    return ranges.get(suffix, 0)

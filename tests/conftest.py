"""Respuesta falsa de la API de HIBP (Pwned Passwords), calculada con los
hashes SHA-1 reales de las contraseñas de prueba, para no depender de
internet ni de la API real en los tests."""
from __future__ import annotations

import pytest

# password123  -> CBFDA C6008F9CAB4083784CBD1874F76618D2A97  (filtrada)
# qwerty       -> B1B37 73A05C0ED0176787A4F1574FF0075F7521E  (filtrada)
# Tr0ub4dor&3xyz99 -> FDD59 875A85DDAB279073FD5125F866E13D10805 (NO filtrada)
FAKE_RANGES = {
    "CBFDA": {
        "C6008F9CAB4083784CBD1874F76618D2A97": 2000000,
        "1111111111111111111111111111111111": 3,
    },
    "FDD59": {
        "2222222222222222222222222222222222": 1,  # el sufijo real no está: "no filtrada"
    },
    "B1B37": {
        "73A05C0ED0176787A4F1574FF0075F7521E": 4500000,
    },
}


class FakeResponse:
    def __init__(self, text: str):
        self.text = text

    def raise_for_status(self):
        pass


def fake_requests_get(url, timeout=None, headers=None):
    prefix = url.rsplit("/", 1)[-1]
    entries = FAKE_RANGES.get(prefix, {})
    body = "\r\n".join(f"{suffix}:{count}" for suffix, count in entries.items())
    return FakeResponse(body)


@pytest.fixture(autouse=True)
def fake_hibp(monkeypatch):
    monkeypatch.setattr("pwcheck.hibp.requests.get", fake_requests_get)

"""Reglas locales de fortaleza de contraseña. No hace ninguna petición de
red: todo se calcula sobre el texto que ya tienes en memoria."""
from __future__ import annotations

import re

MIN_LENGTH = 12
COMMON_WEAK = {
    "password", "123456", "123456789", "qwerty", "111111", "12345678",
    "abc123", "password1", "admin", "letmein", "welcome", "contraseña",
    "123123", "iloveyou", "monkey", "dragon", "qwerty123",
}


def check_policy(password: str) -> list[str]:
    """Devuelve una lista de observaciones (vacía = sin objeciones). Nunca
    incluye la contraseña en el texto de la observación."""
    notes: list[str] = []
    if len(password) < MIN_LENGTH:
        notes.append(f"Longitud {len(password)} caracteres, se recomiendan al menos {MIN_LENGTH}.")

    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if classes < 3:
        notes.append("Usa menos de 3 tipos de carácter (minúscula/mayúscula/dígito/símbolo).")

    if re.search(r"(.)\1{2,}", password):
        notes.append("Contiene 3 o más caracteres repetidos seguidos.")

    if password.lower() in COMMON_WEAK:
        notes.append("Es una de las contraseñas más comunes del mundo.")

    return notes

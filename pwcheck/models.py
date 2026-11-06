"""Modelos de datos. Regla de diseño clave: ninguna de estas clases tiene
un campo para la contraseña en texto plano. 'label' identifica la entrada
(un nombre de usuario, o 'línea N') pero nunca el secreto en sí."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class PasswordCheck:
    label: str
    breach_count: int
    policy_notes: list[str] = field(default_factory=list)

    @property
    def breached(self) -> bool:
        return self.breach_count > 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["breached"] = self.breached
        return d


@dataclass
class AuditResult:
    checked_at: str
    results: list[PasswordCheck] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        return {
            "total": len(self.results),
            "filtradas": sum(1 for r in self.results if r.breached),
            "con_observaciones": sum(1 for r in self.results if r.policy_notes),
        }

    def to_dict(self) -> dict:
        return {
            "checked_at": self.checked_at,
            "summary": self.summary(),
            "results": [r.to_dict() for r in self.results],
            "errors": self.errors,
        }

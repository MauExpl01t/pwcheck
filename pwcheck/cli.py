"""Interfaz de línea de comandos: pwcheck check | pwcheck audit <archivo>"""
from __future__ import annotations

import argparse
import getpass
import sys

from . import __version__, hibp, policy
from .auditor import audit_file
from .report import to_html, to_json, to_text

LEGAL = ("AVISO: revisa solo contraseñas tuyas o que tengas autorización legítima para "
         "poseer (p. ej. obtenidas en un pentest autorizado). La contraseña nunca se "
         "envía completa por la red (k-anonimato) ni queda guardada por esta herramienta.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pwcheck", description="Auditoría de contraseñas filtradas. " + LEGAL)
    p.add_argument("--version", action="version", version=f"pwcheck {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check", help="Revisa una sola contraseña (entrada oculta, interactiva)")

    a = sub.add_parser("audit", help="Revisa un archivo con varias contraseñas")
    a.add_argument("file", help="Archivo: una contraseña por línea, o 'usuario:contraseña'")
    a.add_argument("--format", choices=["text", "json", "html"], default="text")
    a.add_argument("-o", "--output", help="Archivo de salida (por defecto stdout)")
    return p


def run_check() -> int:
    print(LEGAL, file=sys.stderr)
    password = getpass.getpass("Contraseña a revisar (no se muestra en pantalla): ")
    if not password:
        print("No se ingresó nada.", file=sys.stderr)
        return 1
    try:
        count = hibp.breach_count(password)
    except Exception as exc:
        print(f"No se pudo consultar: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    notes = policy.check_policy(password)
    del password  # fuera de uso lo antes posible

    if count:
        print(f"⚠ Esta contraseña apareció en filtraciones conocidas {count:,} veces. Cámbiala.")
    else:
        print("✓ No aparece en la base de datos de contraseñas filtradas conocidas.")
    for note in notes:
        print(f"  - {note}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "check":
        return run_check()

    print(LEGAL, file=sys.stderr)
    result = audit_file(args.file)
    if args.format == "json":
        out = to_json(result)
    elif args.format == "html":
        out = to_html(result)
    else:
        out = to_text(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Reporte guardado en {args.output}")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

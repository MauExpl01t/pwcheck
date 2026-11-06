"""Reportes en texto, JSON y HTML. Ninguno de los tres incluye jamás la
contraseña en texto plano: solo la etiqueta (usuario o número de línea),
si apareció en filtraciones y cuántas veces, y observaciones de política."""
from __future__ import annotations

import json
from html import escape

from .models import AuditResult


def to_json(result: AuditResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def to_text(result: AuditResult) -> str:
    summ = result.summary()
    lines = [f"Revisadas    : {summ['total']}",
              f"Filtradas    : {summ['filtradas']}",
              f"Con observ.  : {summ['con_observaciones']}", ""]
    for r in result.results:
        estado = f"FILTRADA ({r.breach_count:,} veces)" if r.breached else "sin filtración conocida"
        lines.append(f"[{estado}] {r.label}")
        for note in r.policy_notes:
            lines.append(f"    - {note}")
    for e in result.errors:
        lines.append(f"[!] {e}")
    return "\n".join(lines)


def to_html(result: AuditResult) -> str:
    summ = result.summary()
    rows = []
    for r in result.results:
        sev = "#b91c1c" if r.breached else "#16a34a"
        estado = f"Filtrada ({r.breach_count:,} veces)" if r.breached else "Sin filtración conocida"
        notes = "".join(f"<li>{escape(n)}</li>" for n in r.policy_notes)
        notes = f"<ul>{notes}</ul>" if notes else ""
        rows.append(
            f'<tr><td>{escape(r.label)}</td>'
            f'<td style="color:{sev};font-weight:600">{escape(estado)}</td>'
            f'<td>{notes}</td></tr>')
    errs = "".join(f"<li>{escape(e)}</li>" for e in result.errors)
    errs = f"<h2>Advertencias</h2><ul>{errs}</ul>" if errs else ""

    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PwCheck - auditoría de contraseñas</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#0f172a;background:#f8fafc}}
h1{{margin-bottom:.2rem}} .meta{{color:#475569}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;margin-top:1rem}}
th,td{{text-align:left;padding:.5rem .7rem;border-bottom:1px solid #e2e8f0;font-size:.9rem;vertical-align:top}}
th{{background:#f1f5f9}}
.chip{{display:inline-block;background:#e2e8f0;padding:.2rem .6rem;border-radius:999px;margin-right:.4rem;font-size:.85rem}}
</style></head><body>
<h1>Auditoría de contraseñas (PwCheck)</h1>
<p class="meta">{escape(result.checked_at)}</p>
<p><span class="chip">Revisadas: {summ['total']}</span>
<span class="chip">Filtradas: {summ['filtradas']}</span>
<span class="chip">Con observaciones: {summ['con_observaciones']}</span></p>
{errs}
<table><tr><th>Usuario / línea</th><th>Estado</th><th>Observaciones de política</th></tr>
{''.join(rows) or '<tr><td colspan="3">Sin datos.</td></tr>'}
</table>
<p class="meta">Este reporte nunca incluye las contraseñas en texto plano, solo el resultado de la verificación.</p>
</body></html>"""

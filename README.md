# PwCheck

![Tests](https://github.com/MauExpl01t/pwcheck/actions/workflows/tests.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.12-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Auditoría de contraseñas filtradas en Python, hermana de [WebScan](../webscan)
y [SubdomainEnum](../subdomain-enum). Revisa si una contraseña ya apareció
en alguna filtración de datos conocida — sin que la contraseña salga nunca
completa de tu computador.

> ⚠️ Revisa solo contraseñas tuyas o que tengas autorización legítima para
> poseer (por ejemplo, obtenidas al crackear hashes en un pentest
> autorizado). Esta herramienta nunca guarda ni muestra las contraseñas en
> texto plano.

## Cómo funciona (k-anonimato)

Usa la API pública **Pwned Passwords** de [HaveIBeenPwned](https://haveibeenpwned.com/Passwords),
con la misma técnica que usan 1Password, Firefox y Chrome para esta función:

1. Se calcula el hash SHA-1 de la contraseña, en tu propio computador.
2. Solo se envían los **primeros 5 caracteres** de ese hash al servidor.
3. El servidor responde con todas las contraseñas filtradas que comparten
   ese prefijo (normalmente cientos) y cuántas veces apareció cada una.
4. La comparación exacta se hace localmente, con el resto del hash.

La contraseña completa, y su hash completo, **nunca viajan por la red**.
No se necesita API key: es un endpoint público pensado exactamente para
este uso.

## Instalación (Windows / PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Uso

```powershell
# Revisa una sola contraseña (entrada oculta, no se muestra en pantalla)
python -m pwcheck check

# Revisa un archivo con varias (una por línea, o "usuario:contraseña")
python -m pwcheck audit contraseñas.txt

# Reporte en HTML o JSON
python -m pwcheck audit contraseñas.txt --format html -o reporte.html
```

Ejemplo de archivo para `audit`:
```
ana:MiClave2024
carlos:Tr0ub4dor&3xyz99
password123
```

## Qué más revisa (sin red, local)

Además de la filtración, cada contraseña se evalúa contra reglas básicas
de fortaleza: longitud mínima (12 caracteres), variedad de tipos de
carácter, caracteres repetidos seguidos, y si es una de las contraseñas
más comunes del mundo.

## Seguridad de la propia herramienta

- **La contraseña nunca se guarda ni se imprime**: ni en el reporte, ni en
  los modelos de datos internos, ni en logs. Solo se reporta la etiqueta
  (usuario o número de línea) y el veredicto.
- `check` usa entrada oculta (`getpass`): la contraseña no aparece en
  pantalla ni queda en el historial de la terminal.
- Cachea las consultas por prefijo de hash durante una auditoría masiva,
  para no repetir peticiones si varias personas eligieron la misma
  contraseña.

## Pruebas

```powershell
python -m pytest -q
```

Incluye un test que confirma explícitamente que la contraseña nunca
aparece en ningún reporte generado.

## Ideas para siguientes versiones

- Integrarlo como librería dentro de un formulario de registro/cambio de
  contraseña, para rechazar contraseñas filtradas en el momento.
- Exportar el reporte sin ninguna etiqueta identificable (solo conteos
  agregados), para compartir resultados de una auditoría sin exponer
  qué usuario tiene qué problema.

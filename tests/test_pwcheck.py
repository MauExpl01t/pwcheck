import pytest

from pwcheck import hibp, policy
from pwcheck.auditor import audit_file, parse_line
from pwcheck.report import to_html, to_json, to_text


# ---------- hibp (k-anonimato) ----------
def test_breached_password_detected():
    assert hibp.breach_count("password123") == 2000000


def test_safe_password_not_flagged():
    assert hibp.breach_count("Tr0ub4dor&3xyz99") == 0


def test_only_prefix_is_sent_to_the_network(monkeypatch):
    from conftest import FakeResponse

    sent = {}

    def spy_get(url, timeout=None, headers=None):
        sent["url"] = url
        return FakeResponse("C6008F9CAB4083784CBD1874F76618D2A97:2000000")

    monkeypatch.setattr("pwcheck.hibp.requests.get", spy_get)
    hibp.breach_count("password123")
    assert sent["url"].endswith("/range/CBFDA")
    assert "password123" not in sent["url"]


# ---------- policy (reglas locales) ----------
def test_policy_flags_short_password():
    notes = policy.check_policy("abc123")
    assert any("Longitud" in n for n in notes)


def test_policy_flags_common_password():
    notes = policy.check_policy("password")
    assert any("comunes" in n for n in notes)


def test_policy_accepts_strong_password():
    assert policy.check_policy("Tr0ub4dor&3xyz99Zq!") == []


# ---------- auditor (archivo masivo) ----------
def test_parse_line_with_username():
    assert parse_line("ana:password123\n", 1) == ("ana", "password123")


def test_parse_line_without_username():
    assert parse_line("password123\n", 7) == ("línea 7", "password123")


def test_parse_line_skips_blank():
    assert parse_line("   \n", 3) is None


def test_audit_file_end_to_end(tmp_path):
    f = tmp_path / "passwords.txt"
    f.write_text("ana:password123\ncarlos:Tr0ub4dor&3xyz99\nqwerty\n", encoding="utf-8")

    result = audit_file(str(f))
    by_label = {r.label: r for r in result.results}

    assert by_label["ana"].breached is True
    assert by_label["ana"].breach_count == 2000000
    assert by_label["carlos"].breached is False
    assert by_label["línea 3"].breached is True  # "qwerty", sin usuario


def test_audit_summary_counts_correctly(tmp_path):
    f = tmp_path / "passwords.txt"
    f.write_text("ana:password123\ncarlos:Tr0ub4dor&3xyz99Zq!\n", encoding="utf-8")
    result = audit_file(str(f))
    summ = result.summary()
    assert summ["total"] == 2
    assert summ["filtradas"] == 1


# ---------- reportes: la contraseña NUNCA debe aparecer ----------
def test_reports_never_contain_the_plaintext_password(tmp_path):
    secret = "password123"
    f = tmp_path / "passwords.txt"
    f.write_text(f"ana:{secret}\n", encoding="utf-8")
    result = audit_file(str(f))

    assert secret not in to_text(result)
    assert secret not in to_json(result)
    assert secret not in to_html(result)
    # pero sí debe aparecer la etiqueta y el veredicto
    assert "ana" in to_text(result)
    assert "2,000,000" in to_text(result) or "2000000" in to_json(result)

from pwcheck.cli import main


def test_audit_runs_end_to_end(tmp_path, capsys):
    f = tmp_path / "passwords.txt"
    f.write_text("ana:password123\ncarlos:Tr0ub4dor&3xyz99\n", encoding="utf-8")
    rc = main(["audit", str(f)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ana" in out
    assert "password123" not in out  # la contraseña nunca debe imprimirse


def test_check_reports_breached_password(monkeypatch, capsys):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "password123")
    rc = main(["check"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "2,000,000" in out
    assert "password123" not in out


def test_check_reports_safe_password(monkeypatch, capsys):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "Tr0ub4dor&3xyz99")
    rc = main(["check"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No aparece" in out

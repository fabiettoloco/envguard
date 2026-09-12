from pathlib import Path

from envguard.scanner import scan

def test_missing_environment_variable(tmp_path: Path):
    (tmp_path / "app.py").write_text('import os\nurl = os.getenv("DATABASE_URL")\n')
    (tmp_path / ".env.example").write_text("PORT=8000\n")
    findings = scan(tmp_path)
    assert any(f.kind == "missing-env" and "DATABASE_URL" in f.message for f in findings)

def test_stale_environment_variable(tmp_path: Path):
    (tmp_path / "app.py").write_text('print("hello")\n')
    (tmp_path / ".env.example").write_text("OLD_SETTING=value\n")
    findings = scan(tmp_path)
    assert any(f.kind == "stale-env" for f in findings)

def test_secret_detection(tmp_path: Path):
    (tmp_path / "config.py").write_text('AWS_SECRET_ACCESS_KEY = "12345678901234567890"\n')
    findings = scan(tmp_path)
    assert any(f.kind == "secret" for f in findings)

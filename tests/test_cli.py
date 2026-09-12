from pathlib import Path

from envguard.cli import main


def test_scan_missing_path(capsys):
    assert main(["scan", "/definitely/not/a/real/path"]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_scan_quiet(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text('import os\nprint(os.getenv("DATABASE_URL"))\n')
    (tmp_path / ".env.example").write_text("PORT=8000\n")
    assert main(["scan", str(tmp_path), "--quiet"]) == 1
    assert capsys.readouterr().out == ""


def test_scan_json_output(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text('import os\nprint(os.getenv("DATABASE_URL"))\n')
    (tmp_path / ".env.example").write_text("PORT=8000\n")
    assert main(["scan", str(tmp_path), "--format", "json"]) == 1
    assert "missing-env" in capsys.readouterr().out


def test_scan_config_argument_requires_existing_file(tmp_path: Path, capsys):
    assert main(["scan", str(tmp_path), "--config", "missing.toml"]) == 2
    assert "config file does not exist" in capsys.readouterr().err


def test_scan_explicit_config(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text('import os\nprint(os.getenv("DATABASE_URL"))\n')
    (tmp_path / ".env.example").write_text("PORT=8000\n")
    config = tmp_path / "custom.toml"
    config.write_text('[scan]\nallowlist = ["DATABASE_URL"]\n')
    assert main(["scan", str(tmp_path), "--config", str(config)]) == 1
    assert "PORT" in capsys.readouterr().out


def test_scan_verbose_uses_stderr(tmp_path: Path, capsys):
    assert main(["scan", str(tmp_path), "--verbose"]) == 0
    captured = capsys.readouterr()
    assert "Scanning" in captured.err

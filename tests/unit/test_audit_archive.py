"""A7: хук архивации закрытого сегмента журнала.

Команда получает два пути (сегмент и .head), запускается без shell и не может уронить
шлюз: её ошибка пишется событием audit_archive_failed, а ротация уже состоялась.
"""
import pathlib
import sys

import pytest

from gatekeeper.core.events import EventType
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.config import ConfigError, load_config


def segments(tmp_path):
    return sorted(p for p in tmp_path.iterdir()
                  if p.name.startswith("audit.log.") and p.name[-1].isdigit())


def make_chain(tmp_path, command=(), max_bytes=600, keep=100):
    # keep=100: тест не должен зависеть от удаления старых сегментов (ротаций много).
    return AuditChain(FileSink(tmp_path / "audit.log"), max_bytes=max_bytes, keep=keep,
                      archive_command=command)


def test_hook_receives_the_segment_and_its_head(tmp_path):
    out = tmp_path / "hook-args.txt"
    recorder = (
        f"import pathlib,sys;"
        f"pathlib.Path({str(out)!r}).write_text('\\n'.join(sys.argv[1:]))"
    )
    chain = make_chain(tmp_path, (sys.executable, "-c", recorder))
    for i in range(30):
        chain.append(EventType.SERVER_STARTED, {"i": i})
    assert segments(tmp_path), "ротация должна была состояться"
    # Ротаций было несколько: файл перезаписан последним вызовом хука.
    args = out.read_text().split("\n")
    assert len(args) == 2, args
    seg, head = pathlib.Path(args[0]), pathlib.Path(args[1])
    assert seg.exists() and head.exists()
    assert seg.name.startswith("audit.log.") and head.name == seg.name + ".head"
    assert seg.parent == tmp_path
    # Ошибки хука нет: событие не должно появляться.
    assert "audit_archive_failed" not in (tmp_path / "audit.log").read_text()


def test_failing_hook_does_not_stop_the_log(tmp_path):
    chain = make_chain(tmp_path, (sys.executable, "-c", "import sys; sys.exit(3)"))
    for i in range(30):
        chain.append(EventType.SERVER_STARTED, {"i": i})
    text = (tmp_path / "audit.log").read_text()
    assert "audit_archive_failed" in text
    assert "exit_code_3" in text.replace(" ", "")
    assert chain.append(EventType.SERVER_STARTED, {"after": True})["seq"] >= 0


def test_missing_hook_binary_is_reported(tmp_path):
    chain = make_chain(tmp_path, (str(tmp_path / "no-such-hook"),))
    for i in range(30):
        chain.append(EventType.SERVER_STARTED, {"i": i})
    # События об ошибке попадают в сегмент, который затем сам уходит в архив.
    files = [tmp_path / "audit.log", *segments(tmp_path)]
    text = "".join(f.read_text() for f in files if f.exists())
    # Точное число зависит от того, перерос ли сегмент лимит: важен сам факт события.
    assert 1 <= text.count("audit_archive_failed") <= len(segments(tmp_path))
    assert "FileNotFoundError" in text


def test_hook_is_off_by_default(tmp_path):
    chain = make_chain(tmp_path)
    for i in range(30):
        chain.append(EventType.SERVER_STARTED, {"i": i})
    assert segments(tmp_path)                   # ротация работает как раньше
    assert "audit_archive_failed" not in (tmp_path / "audit.log").read_text()


def test_config_accepts_and_validates_archive_command(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("", encoding="utf-8")
    assert load_config(p).audit_archive_command == ()          # старый конфиг не ломается
    p.write_text('[audit]\narchive_command = ["/bin/true", "--flag"]\n', encoding="utf-8")
    assert load_config(p).audit_archive_command == ("/bin/true", "--flag")
    for bad in ('[audit]\narchive_command = "true"\n',
                '[audit]\narchive_command = ["/bin/true", 1]\n',
                '[audit]\narchive_command = [""]\n'):
        p.write_text(bad, encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(p)

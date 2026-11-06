import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from security_monitor import config, deploy, engine, health, notifier, scanner
from security_monitor.feeds import HTTPFailure
from security_monitor.storage import Store
from security_monitor.util import MonitorError, utcnow
from security_monitor.versions import wp_affected


class FailureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cfg = {**config.defaults(), "state_dir": str(self.root / "state"), "notifications_enabled": True}

    def tearDown(self):
        self.tmp.cleanup()

    def test_utf16_parts_do_not_cut_or_truncate(self):
        message = "абв🚨" * 2000
        parts = notifier.message_parts(message)
        self.assertEqual("".join(parts), message)
        self.assertTrue(all(len(p.encode("utf-16-le")) // 2 <= 3500 for p in parts))

    def test_partial_delivery_resumes_after_reopen(self):
        calls = []
        credentials = {"TELEGRAM_BOT_TOKEN": "fake", "TELEGRAM_CHAT_ID": "fake"}
        def accept(url, **kwargs):
            calls.append(json.loads(kwargs["data"])["text"])
            return 200, {}, {"ok": True, "result": {"message_id": len(calls)}}
        with Store(self.cfg["state_dir"]) as store:
            with store.db:
                store.queue("long", {"kind": "test", "text": "x" * 5000, "notices": [{"notice": "License 🚨" * 1000}]})
            small_budget = {**self.cfg, "max_notifications_per_run": 1}
            first = notifier.flush(store, small_budget, credentials, accept)
            self.assertEqual(first["parts_sent"], 1)
            self.assertEqual(first["sent"], 0)
        with Store(self.cfg["state_dir"]) as store:
            result = notifier.flush(store, self.cfg, credentials, accept)
            self.assertEqual(result["sent"], 1)
            self.assertEqual(notifier.flush(store, self.cfg, credentials, accept)["sent"], 0)
        self.assertGreater(len(calls), 1)
        self.assertNotEqual(calls[0], calls[1])
        self.assertIn("License", "".join(calls))

    def test_telegram_429_does_not_drop_queue(self):
        with Store(self.cfg["state_dir"]) as store:
            with store.db:
                store.queue("one", {"kind": "test", "text": "test"}, "P1")
            def fail(*a, **kw):
                raise HTTPFailure("API: HTTP 429", 3600)
            result = notifier.flush(store, self.cfg, {"TELEGRAM_BOT_TOKEN": "fake", "TELEGRAM_CHAT_ID": "fake"}, fail)
            self.assertEqual(result["failed"], 1)
            record = store.db.execute("SELECT * FROM outbox").fetchone()
            self.assertIsNone(record["sent_at"])
            self.assertTrue(record["next_retry"])
            self.assertNotIn("fake", record["last_error"])

    def test_missing_tokens_local_mode_keeps_queue(self):
        with Store(self.cfg["state_dir"]) as store:
            with store.db:
                store.queue("one", {"kind": "test", "text": "test"})
            result = notifier.flush(store, {**self.cfg, "notifications_enabled": False}, {})
            self.assertEqual(result["pending"], 1)
            self.assertEqual(result["mode"], "local")

    def test_install_dry_run_has_no_mutations(self):
        with patch("security_monitor.deploy.inventory.platform_status", return_value={"status": "tested"}), patch("subprocess.run", side_effect=AssertionError("No mutations")):
            plan = deploy.install(self.cfg, dry_run=True)
        self.assertFalse(plan["starts_timers"])
        self.assertFalse(plan["system_packages_changed"])
        self.assertFalse(self.root.joinpath("state").exists())

    def test_unverified_platform_timers_refused(self):
        with patch("security_monitor.deploy.inventory.platform_status", return_value={"status": "experimental"}):
            with self.assertRaises(MonitorError):
                deploy.install(self.cfg, dry_run=True)

    def test_unsupported_host_does_not_start_scan(self):
        with Store(self.cfg["state_dir"]) as store, patch("security_monitor.engine.inventory.platform_status", return_value={"status": "unsupported"}), patch("security_monitor.engine.scanner.scan", side_effect=AssertionError("Must not run")):
            with self.assertRaises(MonitorError):
                engine.scan_targets(store, self.cfg)

    def test_incompatible_sqlite_schema_refused(self):
        state = self.root / "state"
        state.mkdir(mode=0o700)
        with sqlite3.connect(state / "state.sqlite3") as db:
            db.execute("PRAGMA user_version=999")
        with self.assertRaises(MonitorError):
            Store(state)

    def test_all_wordfence_ranges_validated(self):
        body = {"first": {"from_version": "*", "from_inclusive": True, "to_version": "*", "to_inclusive": True}, "broken": {}}
        with self.assertRaises(MonitorError):
            wp_affected("1.0", body)

    def test_config_types_rejected(self):
        for change in [{"server_name": 123}, {"schema": True}, {"scan_timeout": True}, {"notifications_enabled": "yes"}, {"apps": None}]:
            with self.subTest(change=change), self.assertRaises(MonitorError):
                config.validate({**self.cfg, **change})

    def test_config_preserves_service_read_permissions(self):
        path = self.root / "config.json"
        config.save(path, self.cfg)
        path.chmod(0o640)
        config.save(path, self.cfg)
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_scanner_rejects_tampered_binary_before_execution(self):
        path = self.root / "trivy"
        path.write_text("malicious executable")
        with patch("security_monitor.scanner.run", side_effect=AssertionError("No execution")):
            with self.assertRaises(MonitorError):
                scanner.executable({**self.cfg, "trivy_path": str(path)})

    def test_doctor_missing_tools_is_degraded(self):
        with Store(self.cfg["state_dir"]) as store, patch("security_monitor.health.scanner.executable", side_effect=MonitorError("missing")):
            result = health.evaluate(store, self.cfg, doctor=True)
            self.assertEqual(result["status"], "degraded")
            self.assertEqual(result["checks"]["trivy"], "missing")

    def test_stale_db_does_not_publish_artifact(self):
        def fake_run(argv, **kw):
            out = Path(argv[argv.index("--output") + 1])
            out.write_text('{"kind":"schema","version":1}\n{"kind":"target","class":"os-pkgs","type":"ubuntu"}\n{"kind":"complete","version":1}\n')
            meta = Path(self.cfg["state_dir"]) / "cache/trivy/db/metadata.json"
            meta.parent.mkdir(parents=True)
            meta.write_text(json.dumps({"UpdatedAt": "2000-01-01T00:00:00Z"}))
            return "", ""
        with patch("security_monitor.scanner.executable", return_value="fake-trivy"), patch("security_monitor.scanner.run", side_effect=fake_run):
            with self.assertRaises(MonitorError):
                scanner.scan(self.cfg)
        self.assertEqual(list((self.root / "state/artifacts").iterdir()), [])

    def test_scanner_timeout_does_not_touch_previous_artifacts(self):
        artifacts = self.root / "state/artifacts"
        artifacts.mkdir(parents=True)
        previous = artifacts / "previous.jsonl"
        previous.write_text("previous-valid-result")
        with patch("security_monitor.scanner.executable", return_value="fake-trivy"), patch("security_monitor.scanner.run", side_effect=MonitorError("timeout")):
            with self.assertRaises(MonitorError):
                scanner.scan(self.cfg)
        self.assertEqual(previous.read_text(), "previous-valid-result")


if __name__ == "__main__":
    unittest.main()

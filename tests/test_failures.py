import json
import io
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
    def test_baseline_marks_mixed_example_priorities(self):
        message = notifier.render(self.cfg, {"kind": "baseline", "count": 2, "counts": {"P1": 1, "P3": 1},
                 "details": [{"priority": "P1", "vuln": "CVE-2026-1111"}, {"priority": "P3", "vuln": "CVE-2026-2222"}]}, "P1")
        self.assertIn("СВОДКА (максимум P1)", message)
        self.assertIn("P3 · CVE-2026-2222", message)

    def test_wordfence_429_waits_at_least_thirty_minutes(self):
        from security_monitor import feeds
        from security_monitor.util import age_seconds
        def limited(*a, **kw):
            raise HTTPFailure("API: HTTP 429", 60)
        with Store(self.cfg["state_dir"]) as store:
            self.assertEqual(feeds.refresh(store, "wordfence", {"WORDFENCE_API_KEY": "fake"}, limited)["status"], "error")
            self.assertGreater(-age_seconds(store.meta("retry-feed:wordfence")["until"]), 1790)

    def test_telegram_uses_explicit_proxy(self):
        seen = {}
        def accept(url, **kwargs):
            seen.update(kwargs)
            return 200, {}, {"ok": True, "result": {"message_id": 1}}
        notifier.send({"TELEGRAM_BOT_TOKEN": "fake", "TELEGRAM_CHAT_ID": "fake"}, "test", accept,
                      proxy_url="http://127.0.0.1:3128")
        self.assertEqual(seen["proxy_url"], "http://127.0.0.1:3128")

    def test_proxy_config_rejects_credentials_and_invalid_urls(self):
        for value in (None, 42, "socks5://localhost:1080", "http://a:b@localhost:3128", "http://localhost:bad", "http://localhost/path"):
            with self.subTest(value=value), self.assertRaises(MonitorError):
                config.validate({**self.cfg, "telegram_proxy_url": value})
        config.validate({**self.cfg, "telegram_proxy_url": "http://127.0.0.1:3128"})

    def test_wordfence_stream_matches_full_validation(self):
        from security_monitor import feeds
        from test_core import wf
        body = json.dumps(wf(), ensure_ascii=False).encode()
        class Chunked(io.BytesIO):
            def read(self, size=-1):
                return super().read(min(size, 7))
        self.assertEqual(feeds.read_wordfence(Chunked(body)), feeds.validate_wordfence(wf()))

    def test_wordfence_stream_rejects_truncation_trailing_and_duplicate(self):
        from security_monitor import feeds
        from test_core import wf
        raw = json.dumps(wf())
        for body in (raw[:-1], raw + "{}", raw[:-1] + "," + raw[1:], "{}", raw + "\ufffd"):
            with self.subTest(body=body[-15:]), self.assertRaises(MonitorError):
                feeds.read_wordfence(io.BytesIO(body.encode()))
        with self.assertRaises(MonitorError):
            feeds.read_wordfence(io.BytesIO(b'{"x":"\xff"}'))

    def test_wordfence_stream_size_limits(self):
        from security_monitor import feeds
        from test_core import wf
        body = json.dumps(wf()).encode()
        for limits in ({"limit": 10}, {"record_limit": 10}):
            with self.subTest(limits=limits), self.assertRaises(MonitorError):
                feeds.read_wordfence(io.BytesIO(body), **limits)

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

    def test_child_commands_use_readable_root_cwd(self):
        from security_monitor.util import run
        text, _ = run([sys.executable, "-c", "import os; print(os.getcwd())"])
        self.assertEqual(text.strip(), "/")

    def test_child_file_size_limit_is_enforced(self):
        from security_monitor.util import run
        with self.assertRaises(MonitorError):
            run([sys.executable, "-c", "import os; os.write(1,b'x'*65536); os.write(1,b'x')"], file_limit=1024)

    def test_completed_scan_cannot_erase_new_kev_evidence(self):
        from test_core import row
        with Store(self.cfg["state_dir"]) as store:
            store.reconcile("os", [row(kev=False)], {}, engine.verify_os)
            engine.enrich_kev(store, {"CVE-2026-1234"})
            store.reconcile("os", [row(kev=False)], {}, engine.verify_os)
            result = list(store.findings())[0]
            self.assertTrue(result["kev"])
            self.assertEqual(result["priority"], "P1")

    def test_removing_scope_does_not_hide_open_findings(self):
        from test_core import row
        with Store(self.cfg["state_dir"]) as store:
            store.reconcile("apps:removed", [row()], {}, engine.verify_dependency)
            report = health.evaluate(store, self.cfg)
            self.assertIn("disabled_with_open_findings", [x["status"] for x in report["adapters"]])

    def test_maintenance_never_deletes_unsent_notifications(self):
        with Store(self.cfg["state_dir"]) as store:
            with store.db:
                store.queue("pending", {"kind": "test"})
                store.queue("sent", {"kind": "test"})
                store.db.execute("UPDATE outbox SET created_at='2000-01-01T00:00:00+00:00'")
                store.db.execute("UPDATE outbox SET sent_at='2000-01-01T00:00:00+00:00' WHERE event_key='sent'")
            store.maintenance()
            rows = store.db.execute("SELECT event_key FROM outbox").fetchall()
            self.assertEqual([r[0] for r in rows], ["pending"])

    def test_wordfence_aliases_merge_without_inventing_fix(self):
        from test_core import wf
        from security_monitor import feeds, wordpress
        data = wf()
        second = json.loads(json.dumps(next(iter(data.values()))))
        second["id"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        second["software"][0]["patched_versions"] = ["1.2.5"]
        data[second["id"]] = second
        snapshot = {"components": [{"kind": "plugin", "slug": "example", "version": "1.2.3", "source_verified": True}]}
        rows = wordpress.match_findings(snapshot, feeds.validate_wordfence(data))
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["aliases"]), 2)
        self.assertEqual(rows[0]["fix_status"], "unknown")

    def test_owned_installation_does_not_follow_directory_symlink(self):
        target = self.root / "target"
        target.mkdir()
        (target / ".managed").write_text(deploy.MARKER)
        link = self.root / "installation"
        link.symlink_to(target, target_is_directory=True)
        with patch("security_monitor.deploy.BASE", link):
            self.assertFalse(deploy.owned())
            with self.assertRaises(MonitorError):
                deploy.uninstall(dry_run=True)


if __name__ == "__main__":
    unittest.main()

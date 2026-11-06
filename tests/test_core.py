import datetime as dt
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from security_monitor import config, deploy, engine, feeds, inventory, notifier, report, scanner, wordpress
from security_monitor.storage import Store
from security_monitor.util import BusyError, MonitorError, atomic_write, json_text, lock, redact, run, safe_url, utcnow
from security_monitor.versions import dpkg_ge, wp_affected, wp_compare


def row(**changes):
    return {"component": "openssl", "component_label": "openssl", "vuln": "CVE-2026-1234",
            "installed": "1.0", "vendor_fixed": None, "upstream_fixed": [], "repo_fixed": None,
            "priority": "P2", "severity": "HIGH", "applicability": "affected", "fix_status": "no_vendor_fix_known",
            "source": "ubuntu", "url": "https://ubuntu.com/security/CVE-2026-1234", **changes}


def kev():
    return {"catalogVersion": "2026.11.06", "dateReleased": utcnow(), "count": 1,
            "vulnerabilities": [{"cveID": "CVE-2026-1234", "dateAdded": "2026-11-06"}]}


def wf():
    identifier = "11111111-2222-3333-4444-555555555555"
    return {identifier: {"id": identifier, "title": "Synthetic finding", "cve": "CVE-2026-1234",
                        "software": [{"type": "plugin", "slug": "example", "patched": True,
                                      "patched_versions": ["1.2.4"], "affected_versions": {
                                          "range": {"from_version": "1.0", "from_inclusive": True,
                                                    "to_version": "1.2.3", "to_inclusive": True}}}],
                        "references": ["https://www.wordfence.com/threat-intel/vulnerabilities/example"],
                        "copyrights": {"synthetic": {"notice": "Synthetic fixture, not licensed feed data"}},
                        "cvss": {"score": 9.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cfg = {**config.defaults(), "state_dir": str(self.root / "state"), "secrets_file": str(self.root / "secrets.env")}

    def tearDown(self):
        self.temp.cleanup()

    def store(self):
        return Store(self.cfg["state_dir"])


class ConfigTests(Base):
    def test_defaults_roundtrip(self):
        p = self.root / "config.json"
        config.save(p, self.cfg)
        self.assertEqual(config.load(p), self.cfg)

    def test_unknown_fields_rejected(self):
        p = self.root / "config.json"
        p.write_text('{"auto_update":true}')
        with self.assertRaises(MonitorError):
            config.load(p)

    def test_tokens_not_executed(self):
        p = Path(self.cfg["secrets_file"])
        p.write_text("TELEGRAM_BOT_TOKEN=$(touch hacked)\nTELEGRAM_CHAT_ID=123\n")
        p.chmod(0o600)
        self.assertEqual(config.secrets(self.cfg)["TELEGRAM_BOT_TOKEN"], "$(touch hacked)")
        self.assertFalse((self.root / "hacked").exists())

    def test_loose_permissions_rejected(self):
        p = Path(self.cfg["secrets_file"])
        p.write_text("TELEGRAM_BOT_TOKEN=secret\n")
        p.chmod(0o644)
        with self.assertRaises(MonitorError):
            config.secrets(self.cfg)

    def test_symlink_secret_rejected(self):
        target = self.root / "actual"
        target.write_text("TELEGRAM_BOT_TOKEN=secret")
        target.chmod(0o600)
        Path(self.cfg["secrets_file"]).symlink_to(target)
        with self.assertRaises(MonitorError):
            config.secrets(self.cfg)

    def test_image_requires_digest(self):
        with self.assertRaises(MonitorError):
            config.validate({**self.cfg, "containers": [{"name": "app", "image": "repo:latest"}]})

    def test_name_cannot_inject_paths(self):
        with self.assertRaises(MonitorError):
            config.validate({**self.cfg, "apps": [{"name": "../../etc", "path": "/srv/app"}]})


class VersionTests(Base):
    def test_wp_numeric_and_prerelease(self):
        for a, b in [("1.2", "1.2.0"), ("6.7.1", "6.7.1")]:
            self.assertEqual(wp_compare(a, b), 0)
        for a, b in [("1.2.9", "1.2.10"), ("1.0-beta1", "1.0-RC1"), ("1.0-RC2", "1.0"), ("1.0", "1.0-pl1")]:
            self.assertLess(wp_compare(a, b), 0)

    def test_wp_boundaries_and_star(self):
        ranges = {"r": {"from_version": "*", "from_inclusive": True, "to_version": "1.2.3", "to_inclusive": False}}
        self.assertTrue(wp_affected("1.2.2", ranges))
        self.assertFalse(wp_affected("1.2.3", ranges))
        ranges["r"]["to_version"] = "*"
        self.assertTrue(wp_affected("9.0", ranges))

    def test_unknown_wp_version_is_not_unaffected(self):
        with self.assertRaises(MonitorError):
            wp_affected("trunk", wf()[next(iter(wf()))]["software"][0]["affected_versions"])

    @unittest.skipUnless(shutil.which("dpkg"), "Native DPKG checked on Linux")
    def test_native_backport_epoch_and_tilde(self):
        self.assertTrue(dpkg_ge("1:1.2.3-0ubuntu0.24.04.2", "1:1.2.3-0ubuntu0.24.04.1"))
        self.assertFalse(dpkg_ge("1.0~rc1", "1.0"))
        self.assertTrue(dpkg_ge("2:1.0", "1:99.0"))

    def test_no_shell_version_injection(self):
        self.assertIsNone(dpkg_ge("1.0; touch pwn", "1.1"))


class StateTests(Base):
    def test_baseline_and_identical_run(self):
        with self.store() as store:
            one = store.reconcile("os", [row()], {}, engine.verify_os)
            two = store.reconcile("os", [row()], {}, engine.verify_os)
            self.assertTrue(one["baseline"])
            self.assertFalse(two["baseline"])
            self.assertEqual(two["events"], 0)
            self.assertEqual(store.db.execute("SELECT count(*) FROM outbox").fetchone()[0], 1)

    def test_separate_assets_are_not_deduplicated(self):
        with self.store() as store:
            for scope in ["wordpress:one", "wordpress:two"]:
                store.reconcile(scope, [row()], {}, engine.verify_os)
            self.assertEqual(len(list(store.findings())), 2)

    def test_scan_failure_does_not_close_or_reset_baseline(self):
        with self.store() as store:
            store.reconcile("os", [row()], {}, engine.verify_os)
            store.run_failed("os", "timeout")
            store.run_failed("os", "timeout")
            self.assertEqual(list(store.findings())[0]["remediation"], "open")
            self.assertEqual(store.db.execute("SELECT count(*) FROM outbox").fetchone()[0], 2)
            self.assertTrue(store.meta("baseline:os"))

    def test_missing_finding_not_automatically_fixed(self):
        with self.store() as store:
            store.reconcile("os", [row()], {}, engine.verify_os)
            store.reconcile("os", [], {"packages": {}}, engine.verify_os)
            self.assertEqual(list(store.findings())[0]["remediation"], "needs_reverification")

    def test_fix_published_and_repo_available_are_distinct(self):
        with self.store() as store:
            store.reconcile("os", [row()], {}, engine.verify_os)
            changed = row(vendor_fixed="1.1", fix_status="vendor_fix_available")
            store.reconcile("os", [changed], {}, engine.verify_os)
            changed.update(fix_status="repo_fix_available", repo_fixed="1.2")
            store.reconcile("os", [changed], {}, engine.verify_os)
            kinds = [r[0] for r in store.db.execute("SELECT kind FROM events")]
            self.assertIn("fix_published", kinds)
            self.assertIn("repo_fix_available", kinds)
            self.assertEqual(list(store.findings())[0]["remediation"], "open")

    def test_updated_package_requires_repeat_verification(self):
        previous = row(vendor_fixed="1.1")
        snapshot = {"platform": {"id": "ubuntu"}, "packages": {"openssl": {"version": "1.2", "origin": "Ubuntu"}}}
        with patch("security_monitor.engine.dpkg_ge", return_value=True):
            self.assertEqual(engine.verify_os(previous, snapshot)["remediation"], "remediated_verified")
        snapshot["packages"]["openssl"]["origin"] = "third_party"
        self.assertEqual(engine.verify_os(previous, snapshot)["remediation"], "update_installed_pending_verification")

    def test_kev_event_once_and_no_false_scan_freshness(self):
        with self.store() as store:
            store.reconcile("os", [row()], {}, engine.verify_os)
            store.db.execute("UPDATE runs SET last_success='2000-01-01T00:00:00+00:00'")
            store.db.commit()
            self.assertEqual(engine.enrich_kev(store, {"CVE-2026-1234"}), 1)
            self.assertEqual(engine.enrich_kev(store, {"CVE-2026-1234"}), 0)
            self.assertEqual(list(store.findings())[0]["priority"], "P1")
            self.assertEqual(store.db.execute("SELECT last_success FROM runs").fetchone()[0], "2000-01-01T00:00:00+00:00")

    def test_transaction_rolls_back_malformed_duplicate(self):
        with self.store() as store:
            with self.assertRaises(MonitorError):
                store.reconcile("os", [row(), row(installed="0.9")], {}, engine.verify_os)
            self.assertEqual(list(store.findings()), [])
            self.assertFalse(store.meta("baseline:os", False))

    def test_backup_and_restore_on_copy(self):
        with self.store() as store:
            store.reconcile("os", [row()], {}, engine.verify_os)
            dest = self.root / "backup.sqlite3"
            store.backup(dest)
        with sqlite3.connect(dest) as db:
            self.assertEqual(db.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(db.execute("SELECT count(*) FROM findings").fetchone()[0], 1)


class FeedAndNotifyTests(Base):
    def test_kev_validation(self):
        self.assertIn("CVE-2026-1234", feeds.validate_kev(kev())["records"])
        for body in [{}, {**kev(), "count": 2}, {**kev(), "vulnerabilities": []}]:
            with self.assertRaises(MonitorError):
                feeds.validate_kev(body)

    def test_304_and_feed_failure_preserve_previous(self):
        with self.store() as store:
            fetch = lambda *a, **k: (200, {"ETag": '"one"'}, kev())
            self.assertEqual(feeds.refresh(store, "kev", {}, fetch)["status"], "fresh")
            self.assertEqual(feeds.refresh(store, "kev", {}, lambda *a, **k: (304, {}, None))["status"], "fresh")
            def failed(*a, **k):
                raise feeds.HTTPFailure("API: HTTP 429", 600)
            self.assertEqual(feeds.refresh(store, "kev", {}, failed)["status"], "error")
            self.assertIn("CVE-2026-1234", feeds.cached(store, "kev", 48)["records"])
            self.assertEqual(feeds.refresh(store, "kev", {}, fetch)["status"], "backoff")

    def test_wordfence_feed_and_metadata(self):
        data = feeds.validate_wordfence(wf())
        snapshot = {"components": [{"kind": "plugin", "slug": "example", "version": "1.2.3", "source_verified": True}]}
        rows = wordpress.match_findings(snapshot, data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["vuln"], "CVE-2026-1234")
        self.assertTrue(rows[0]["notice"])
        snapshot["components"][0]["version"] = "1.2.4"
        self.assertEqual(wordpress.match_findings(snapshot, data), [])

    def test_unknown_wordpress_version_potential(self):
        snapshot = {"components": [{"kind": "plugin", "slug": "example", "version": "custom", "source_verified": True}]}
        row_ = wordpress.match_findings(snapshot, feeds.validate_wordfence(wf()))[0]
        self.assertEqual(row_["applicability"], "potentially_affected")

    def test_static_wp_never_executes_php(self):
        root = self.root / "site"
        (root / "wp-includes").mkdir(parents=True)
        (root / "wp-includes/version.php").write_text("<?php system('touch pwn'); $wp_version = '6.7.1';")
        (root / "wp-content/plugins/example").mkdir(parents=True)
        (root / "wp-content/plugins/example/example.php").write_text("<?php\n/*\nPlugin Name: Example\nVersion: 1.2.3\nPlugin URI: https://wordpress.org/plugins/example/\n*/")
        with patch("subprocess.Popen", side_effect=AssertionError("No PHP/CLI allowed")):
            observed = wordpress.inventory(root)
        self.assertEqual(len(observed["components"]), 2)
        self.assertFalse((root / "pwn").exists())

    def test_telegram_plaintext_and_api_ack(self):
        captured = []
        def fetch(url, **kw):
            captured.append(json.loads(kw["data"]))
            return 200, {}, {"ok": True, "result": {"message_id": 123}}
        self.assertEqual(notifier.send({"TELEGRAM_BOT_TOKEN": "token", "TELEGRAM_CHAT_ID": "chat"}, "<script>_*", fetch), 123)
        self.assertNotIn("parse_mode", captured[0])
        with self.assertRaises(MonitorError):
            notifier.send({"TELEGRAM_BOT_TOKEN": "token", "TELEGRAM_CHAT_ID": "chat"}, "text", lambda *a, **k: (200, {}, {"ok": False}))

    def test_outbox_retry_survives_reopen_and_no_duplicate_success(self):
        cfg = {**self.cfg, "notifications_enabled": True}
        credentials = {"TELEGRAM_BOT_TOKEN": "token", "TELEGRAM_CHAT_ID": "chat"}
        with self.store() as store:
            with store.db:
                store.queue("one", {"kind": "test", "text": "test"})
            def fail(*a, **k):
                raise feeds.HTTPFailure("API: HTTP 500", 60)
            self.assertEqual(notifier.flush(store, cfg, credentials, fail)["failed"], 1)
        with self.store() as store:
            with store.db:
                store.db.execute("UPDATE outbox SET next_retry=NULL")
            success = lambda *a, **k: (200, {}, {"ok": True, "result": {"message_id": 1}})
            self.assertEqual(notifier.flush(store, cfg, credentials, success)["sent"], 1)
            self.assertEqual(notifier.flush(store, cfg, credentials, success)["sent"], 0)


class ScannerAndPolicyTests(Base):
    def write_result(self, lines):
        path = self.root / "result.jsonl"
        path.write_text("\n".join(json.dumps(x) for x in lines))
        return path

    def test_framing_zero_is_valid_empty_is_not(self):
        self.assertEqual(scanner.parse_result(self.write_result([{"kind": "schema", "version": 1}, {"kind": "complete", "version": 1}]))["findings"], [])
        for lines in [[], [{"kind": "schema", "version": 1}], [{"kind": "complete", "version": 1}]]:
            with self.assertRaises(MonitorError):
                scanner.parse_result(self.write_result(lines))

    def test_truncated_json_does_not_parse(self):
        path = self.write_result([{"kind": "schema", "version": 1}])
        with path.open("a") as f:
            f.write('\n{"kind":')
        with self.assertRaises(MonitorError):
            scanner.parse_result(path)

    def test_third_party_never_confirmed_by_ubuntu_source_alone(self):
        item = {"id": "CVE-2026-1234", "pkg": "nodejs", "installed": "22.9.0-1nodesource1", "fixed": "", "severity": "HIGH", "source": {"ID": "ubuntu"}}
        snapshot = {"platform": {"id": "ubuntu"}, "packages": {"nodejs": {"origin": "third_party"}}}
        rows = engine.normalize({"findings": [item], "packages": {}}, snapshot, "os", self.cfg, {"CVE-2026-1234"})
        self.assertEqual(rows[0]["applicability"], "potentially_affected")
        self.assertEqual(rows[0]["priority"], "P3")

    def test_repo_candidate_and_vendor_fix_not_confused(self):
        pkg = {"origin": "Ubuntu", "candidate_origin": "Ubuntu", "candidate": "1.2"}
        with patch("security_monitor.engine.dpkg_ge", return_value=True):
            self.assertEqual(engine.apt_fix(pkg, "1.1", {**self.cfg, "os_id": "ubuntu"}, 60)[0], "repo_fix_available")
            self.assertEqual(engine.apt_fix(pkg, "1.1", {**self.cfg, "os_id": "ubuntu"}, None)[0], "vendor_fix_available")

    def test_policy_origin_associated_with_installed_version(self):
        src = " 500 https://archive.example/ubuntu noble/main amd64 Packages\n     release v=24.04,o=Ubuntu,a=noble,n=noble,l=Ubuntu,c=main,b=amd64\n"
        packages = {"openssl": {"version": "1.0"}}
        pol = "openssl:\n  Installed: 1.0\n  Candidate: 1.1\n  Version table:\n     1.1 500\n        500 https://archive.example/ubuntu noble/main amd64 Packages\n *** 1.0 500\n        500 https://archive.example/ubuntu noble/main amd64 Packages\n        100 /var/lib/dpkg/status\n"
        inventory.parse_policy(pol, packages, inventory.policy_sources(src))
        self.assertEqual(packages["openssl"]["origin"], "Ubuntu")
        self.assertEqual(packages["openssl"]["candidate_origin"], "Ubuntu")

    def test_native_inventory_ignores_removed_configs(self):
        packages = inventory.parse_dpkg("pkg\tamd64\t1.0\tpkg\t1.0\tii \nold\tamd64\t0.1\told\t0.1\trc \n")
        self.assertEqual(set(packages), {"pkg"})

    def test_units_have_no_root_no_docker_no_update(self):
        files = deploy.unit_files(self.cfg)
        self.assertEqual(len(files), 10)
        for name, body in files.items():
            if name.endswith(".service"):
                self.assertIn("User=security-monitor", body)
                self.assertIn("NoNewPrivileges=yes", body)
                self.assertIn("MemoryMax=1G", body)
                self.assertNotIn("apt-get", body)
                self.assertNotIn("SupplementaryGroups=docker", body)
            else:
                self.assertIn("Persistent=true", body)


class PrimitiveTests(Base):
    def test_atomic_write_refuses_symlink(self):
        dest = self.root / "dest"
        dest.write_text("original")
        link = self.root / "link"
        link.symlink_to(dest)
        with self.assertRaises(MonitorError):
            atomic_write(link, "new")
        self.assertEqual(dest.read_text(), "original")

    def test_lock_overlap_refused(self):
        with lock(self.root / "lock"):
            with self.assertRaises(BusyError):
                with lock(self.root / "lock"):
                    pass

    def test_command_output_bounded_and_no_shell(self):
        with self.assertRaises(MonitorError):
            run([sys.executable, "-c", "print('x'*1000)"], max_output=10)
        text, _ = run([sys.executable, "-c", "import sys; print(sys.argv[1])", "$(touch pwn)"])
        self.assertIn("$(touch pwn)", text)

    def test_urls_and_token_redaction(self):
        self.assertEqual(safe_url("javascript:alert(1)"), "")
        self.assertEqual(safe_url("https://user:password@example.com/private"), "")
        self.assertEqual(safe_url("https://example.com/cve?token=x#secret"), "https://example.com/cve")
        self.assertNotIn("123456:abcdefghijklmnopqr", redact("bot123456:abcdefghijklmnopqr"))

    def test_grouping_preserves_assets_and_component_counts(self):
        with self.store() as store:
            store.reconcile("os", [row(source_package="linux"), row(component="linux-tools", source_package="linux")], {}, engine.verify_os)
            store.reconcile("apps:second", [row(source_package="linux")], {}, engine.verify_os)
            groups = report.grouped(store)
            self.assertEqual(len(groups), 2)
            self.assertEqual(sorted(g["links"] for g in groups), [1, 2])


if __name__ == "__main__":
    unittest.main()

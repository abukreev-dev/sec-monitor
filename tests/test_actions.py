import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from security_monitor import actions, engine, notifier, report
from test_core import Base, row


def kernel_snapshot(running="6.8.0-146-generic", fixed_origin="Ubuntu", fixed_image=True):
    packages = {"linux-image-6.8.0-146-generic": {"version": "6.8.0-146.146", "origin": "Ubuntu"}}
    if fixed_image:
        packages["linux-image-6.8.0-147-generic"] = {"version": "6.8.0-147.147", "origin": fixed_origin}
    return {"platform": {"id": "ubuntu"}, "running_kernel": running, "packages": packages}


def kernel_row():
    return row(component="linux-headers-6.8.0-146", component_label="linux-headers-6.8.0-146",
               installed="6.8.0-146.146", vendor_fixed="6.8.0-147.147", kev=True)


def version_ge(a, b):
    return int(a.split("-")[1].split(".")[0]) >= int(b.split("-")[1].split(".")[0])


class ActionTests(Base):
    def test_container_advice_never_tells_admin_to_upgrade_host_package(self):
        finding = row(target_kind="containers", source="ubuntu", upstream_fixed=["1.2"],
                      fix_status="upstream_fix_available")
        plan = actions.recommendation(finding)
        self.assertEqual(plan["code"], "container_rebuild")
        instructions = "\n".join(report.instructions(finding))
        self.assertIn("образ", instructions)
        self.assertNotIn("apt-get", instructions)
        self.assertNotIn("APT metadata", instructions)

    def test_container_image_rescan_does_not_claim_running_deployment_fixed(self):
        finding = row(target_kind="containers", remediation="needs_reverification", upstream_fixed=["1.2"])
        self.assertEqual(actions.recommendation(finding)["code"], "container_reverify")
    def test_installed_fix_does_not_recommend_another_update(self):
        finding = row(installed="1.0", observed_version="1.1", installed_fix_confirmed=True,
                      remediation="update_installed_pending_verification", fix_status="repo_fix_available", repo_fixed="1.1")
        self.assertEqual(actions.recommendation(finding)["code"], "fix_pending_scan")
        text = notifier.render(self.cfg, {"kind": "changes", "count": 1, "kinds": [], "ids": [], "details": [finding]}, "P3")
        self.assertIn("Установлено при последней проверке пакетов: 1.1", text)
        self.assertIn("Исправленная версия уже установлена", text)
        self.assertNotIn("Подготовить ручное обновление", text)

    def test_package_observation_reports_installed_fix_not_repo_only(self):
        package = {"version": "1.1", "origin": "Ubuntu", "candidate": "1.1", "candidate_origin": "Ubuntu", "held": False}
        inventory = {"packages": {"openssl": package}, "apt_age_seconds": 60}
        with self.store() as store:
            store.reconcile("os", [row(installed="1.0", vendor_fixed="1.1")], {}, engine.verify_os)
            with patch("security_monitor.engine.inventory.package_inventory", return_value=inventory), \
                 patch("security_monitor.engine.inventory.os_release", return_value={"ID": "ubuntu"}), \
                 patch("security_monitor.engine.dpkg_ge", return_value=True):
                engine.observe_updates(store, self.cfg)
            finding = json.loads(store.db.execute("select payload from findings").fetchone()[0])
            event = store.db.execute("select kind,payload from events order by id desc limit 1").fetchone()
            self.assertEqual(event["kind"], "update_detected")
            self.assertTrue(finding["installed_fix_confirmed"])
            self.assertEqual(json.loads(event["payload"])["detail"]["observed_version"], "1.1")
            self.assertEqual(finding["action"]["code"], "fix_pending_scan")

    def test_changed_version_without_trusted_fix_does_not_claim_fixed(self):
        finding = row(observed_version="1.1", remediation="update_installed_pending_verification")
        self.assertEqual(actions.recommendation(finding)["code"], "version_pending_scan")

    def test_digest_names_actions_and_preserves_unresolved(self):
        groups = [{"priority": "P2", "component": "openssl", "vuln": "CVE-2026-1234", "action": {"code": "plan_update", "summary": "Обновить пакет"}},
                  {"priority": "P1", "component": "old-kernel", "vuln": "CVE-2026-1235", "action": {"code": "component_absent", "summary": "Пакет отсутствует"}},
                  {"priority": "P3", "component": "sos", "vuln": "CVE-2026-1236", "action": {"code": "fix_pending_scan", "summary": "Ожидается скан"}}]
        text = report.digest_text(groups, "ok")
        self.assertIn("openssl · CVE-2026-1234: Обновить пакет", text)
        self.assertIn("пакет отсутствует в инвентаре: 1", text)
        self.assertIn("исправление установлено, ожидается скан: 1", text)
        self.assertNotIn("Подтверждённых действий для администратора", text)

    def test_userspace_kernel_tools_are_not_fixed_by_reboot(self):
        finding = kernel_row()
        finding["component"] = "linux-tools-6.8.0-146"
        finding["kernel_state"] = "running_fixed_old_package"
        actions.kernel_evidence(finding, kernel_snapshot(running="6.8.0-147-generic"))
        engine.apply_priority(finding, set())
        self.assertNotIn("kernel_state", finding)
        self.assertEqual(finding["priority"], "P1")
        self.assertNotEqual(actions.recommendation(finding)["code"], "inactive_kernel")
    def test_fixed_image_is_not_running_fix(self):
        finding = kernel_row()
        with patch("security_monitor.actions.dpkg_ge", side_effect=version_ge):
            actions.kernel_evidence(finding, kernel_snapshot())
        engine.apply_priority(finding, set())
        plan = actions.recommendation(finding)
        self.assertEqual(finding["kernel_state"], "running_affected_fix_installed")
        self.assertEqual(finding["priority"], "P1")
        self.assertEqual(plan["code"], "reboot_required")
        self.assertIn("6.8.0-146", plan["reason"])
        self.assertIn("6.8.0-147", plan["reason"])

    def test_after_reboot_old_package_remains_open_without_runtime_p1(self):
        finding = kernel_row()
        with patch("security_monitor.actions.dpkg_ge", side_effect=version_ge):
            actions.kernel_evidence(finding, kernel_snapshot(running="6.8.0-147-generic"))
        engine.apply_priority(finding, set())
        self.assertEqual(finding["priority"], "P3")
        self.assertTrue(finding["kev"])
        self.assertEqual(actions.recommendation(finding)["code"], "inactive_kernel")
        self.assertNotEqual(finding.get("remediation"), "remediated_verified")

    def test_removed_old_kernel_does_not_keep_stale_reboot_instruction(self):
        finding = kernel_row()
        with patch("security_monitor.actions.dpkg_ge", side_effect=version_ge):
            actions.kernel_evidence(finding, kernel_snapshot())
            resolution = engine.verify_os(finding, kernel_snapshot(running="6.8.0-147-generic"))
        self.assertEqual(resolution["remediation"], "needs_reverification")
        self.assertEqual(resolution["priority"], "P3")
        self.assertEqual(actions.recommendation({**finding, **resolution})["code"], "inactive_kernel")

    def test_foreign_missing_or_wrong_flavour_image_does_not_claim_reboot_fix(self):
        snapshots = [kernel_snapshot(fixed_origin="third_party"), kernel_snapshot(fixed_image=False)]
        different = kernel_snapshot()
        different["packages"]["linux-image-6.8.0-147-lowlatency"] = different["packages"].pop("linux-image-6.8.0-147-generic")
        snapshots.append(different)
        for snapshot in snapshots:
            with self.subTest(snapshot=snapshot), patch("security_monitor.actions.dpkg_ge", side_effect=version_ge):
                finding = kernel_row()
                actions.kernel_evidence(finding, snapshot)
                self.assertEqual(finding["kernel_state"], "running_affected")

    def test_different_kernel_branch_or_unknown_running_image_requires_review(self):
        for snapshot in [kernel_snapshot(running="6.14.0-1-generic"), kernel_snapshot(running="custom")]:
            finding = kernel_row()
            actions.kernel_evidence(finding, snapshot)
            self.assertEqual(finding["kernel_state"], "unknown")

    def test_action_precedes_counts_and_keeps_manual_boundary(self):
        finding = kernel_row()
        with patch("security_monitor.actions.dpkg_ge", side_effect=version_ge):
            actions.kernel_evidence(finding, kernel_snapshot())
        text = notifier.render(self.cfg, {"kind": "changes", "count": 6, "kinds": [], "ids": [], "details": [finding]}, "P1")
        self.assertLess(text.index("Что делать:"), text.index("Событий:"))
        self.assertIn("Запланировать перезагрузку", text)
        self.assertIn("Монитор ничего не обновляет", text)

    def test_ubuntu_no_fix_is_not_confirmed_from_scanner_status_alone(self):
        snapshot = {"platform": {"id": "ubuntu"}, "packages": {"openssl": {"version": "1.0", "origin": "Ubuntu"}}}
        item = {"id": "CVE-2026-1234", "pkg": "openssl", "installed": "1.0", "fixed": "", "severity": "HIGH",
                "status": "affected", "source": {"ID": "ubuntu"}}
        result = engine.normalize({"findings": [item], "packages": {}}, snapshot, "os", self.cfg, {item["id"]})[0]
        self.assertEqual(result["applicability"], "potentially_affected")
        self.assertEqual(result["scanner_status"], "affected")
        self.assertEqual(result["priority"], "P3")
        self.assertTrue(result["kev"])

    def test_fixed_version_and_investigation_are_distinguished(self):
        snapshot = {"platform": {"id": "ubuntu"}, "packages": {"openssl": {"version": "1.0", "origin": "Ubuntu"}}}
        item = {"id": "CVE-2026-1234", "pkg": "openssl", "installed": "1.0", "fixed": "1.1", "severity": "HIGH",
                "status": "fixed", "source": {"ID": "ubuntu"}}
        first = engine.normalize({"findings": [item], "packages": {}}, snapshot, "os", self.cfg, set())[0]
        self.assertEqual(first["applicability"], "affected")
        item["status"] = "under_investigation"
        second = engine.normalize({"findings": [item], "packages": {}}, snapshot, "os", self.cfg, set())[0]
        self.assertEqual(second["applicability"], "potentially_affected")
        self.assertEqual(second["scanner_status"], "under_investigation")

    def test_p3_reference_changes_go_to_durable_digest_once(self):
        with self.store() as store:
            base = row(priority="P3", severity="LOW")
            store.reconcile("os", [base], {}, engine.verify_os)
            store.reconcile("os", [{**base, "cvss": {"redhat": {"V3Score": 3.3}}}], {}, engine.verify_os)
            self.assertEqual(store.db.execute("SELECT count(*) FROM outbox").fetchone()[0], 1)
            self.assertEqual(store.db.execute("SELECT count(*) FROM digest_events WHERE digested_at IS NULL").fetchone()[0], 1)
        with self.store() as store:
            self.assertTrue(store.queue_digest("2026-11-12", {"kind": "digest", "text": "summary"}))
            payload = json.loads(store.db.execute("SELECT payload FROM outbox WHERE event_key='digest:2026-11-12'").fetchone()[0])
            self.assertEqual(payload["deferred_events"], 1)
            self.assertEqual(payload["deferred_cves"], 1)
            self.assertIn("изменение доказательств: 1", notifier.render(self.cfg, payload, "P3"))
            self.assertFalse(store.queue_digest("2026-11-12", {"kind": "digest"}))
            self.assertEqual(store.db.execute("SELECT count(*) FROM events").fetchone()[0], 2)

    def test_new_p3_is_deferred_but_available_fix_is_immediate(self):
        with self.store() as store:
            base = row(priority="P3", severity="LOW")
            store.reconcile("os", [], {}, engine.verify_os)
            store.reconcile("os", [base], {}, engine.verify_os)
            self.assertEqual(store.db.execute("SELECT count(*) FROM digest_events").fetchone()[0], 1)
            store.reconcile("os", [{**base, "repo_fixed": "1.1", "fix_status": "repo_fix_available"}], {}, engine.verify_os)
            self.assertEqual(store.db.execute("SELECT count(*) FROM outbox WHERE event_key NOT LIKE 'baseline:%'").fetchone()[0], 1)

    def test_same_day_digest_does_not_consume_later_events(self):
        with self.store() as store:
            base = row(priority="P3", severity="LOW")
            store.reconcile("os", [base], {}, engine.verify_os)
            store.queue_digest("2026-11-12", {"kind": "digest"})
            store.reconcile("os", [{**base, "cvss": {"redhat": {"V3Score": 3.3}}}], {}, engine.verify_os)
            self.assertFalse(store.queue_digest("2026-11-12", {"kind": "digest"}))
            self.assertEqual(store.db.execute("SELECT count(*) FROM digest_events WHERE digested_at IS NULL").fetchone()[0], 1)
            store.queue_digest("2026-11-13", {"kind": "digest"})
            self.assertEqual(store.db.execute("SELECT count(*) FROM digest_events WHERE digested_at IS NULL").fetchone()[0], 0)

    def test_potential_kev_new_finding_still_requests_immediate_review(self):
        with self.store() as store:
            store.reconcile("os", [], {}, engine.verify_os)
            store.reconcile("os", [row(priority="P3", kev=True, applicability="potentially_affected")], {}, engine.verify_os)
            self.assertEqual(store.db.execute("SELECT count(*) FROM digest_events").fetchone()[0], 0)
            self.assertEqual(store.db.execute("SELECT count(*) FROM outbox WHERE event_key NOT LIKE 'baseline:%'").fetchone()[0], 1)

    def test_kernel_reboot_transition_notifies_without_closing_old_package(self):
        first, second = kernel_row(), kernel_row()
        with patch("security_monitor.actions.dpkg_ge", side_effect=version_ge):
            actions.kernel_evidence(first, kernel_snapshot())
            actions.kernel_evidence(second, kernel_snapshot(running="6.8.0-147-generic"))
        engine.apply_priority(first, set()); engine.apply_priority(second, set())
        with self.store() as store:
            store.reconcile("os", [first], {}, engine.verify_os)
            store.reconcile("os", [second], {}, engine.verify_os)
            finding = list(store.findings())[0]
            self.assertEqual(finding["priority"], "P3")
            self.assertEqual(finding["remediation"], "open")
            self.assertIn("kernel_runtime_changed", [x[0] for x in store.db.execute("SELECT kind FROM events")])
            self.assertEqual(store.reconcile("os", [second], {}, engine.verify_os)["events"], 0)

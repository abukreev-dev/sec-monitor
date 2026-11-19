import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from security_monitor import containers, config, health, engine
from security_monitor.storage import Store
from security_monitor.util import MonitorError
from security_monitor.util import utcnow
from tempfile import TemporaryDirectory
from unittest.mock import patch


class ContainerInventoryTests(unittest.TestCase):
    def test_inventory_groups_running_containers_by_immutable_local_image(self):
        ids = ['a' * 64, 'b' * 64]
        image = 'sha256:' + 'c' * 64
        lines = ['\t'.join(map(json.dumps, [identifier, image, '/' + name, True]))
                 for identifier, name in zip(ids, ['web', 'worker'])]
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout='\n'.join(ids if len(calls) == 1 else lines))
        result = containers.inventory(run)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['image_id'], image)
        self.assertEqual([x['name'] for x in result[0]['containers']], ['web', 'worker'])
        self.assertIn('--format', calls[1])
        self.assertNotIn('{{json .}}', calls[1])

    def test_changed_or_stopped_container_is_not_silently_accepted(self):
        identifier = 'a' * 64
        def run(argv, **kwargs):
            if argv[1] == 'ps':
                return SimpleNamespace(returncode=0, stdout=identifier)
            line = '\t'.join(map(json.dumps, [identifier, 'sha256:' + 'b' * 64, '/web', False]))
            return SimpleNamespace(returncode=0, stdout=line)
        with self.assertRaises(MonitorError):
            containers.inventory(run)

    def test_docker_failure_is_not_empty_inventory(self):
        with self.assertRaises(MonitorError):
            containers.inventory(lambda *a, **kw: SimpleNamespace(returncode=1, stdout=''))

    def test_inspect_error_does_not_accept_partial_result(self):
        identifier = 'a' * 64
        def run(argv, **kwargs):
            return SimpleNamespace(returncode=0 if argv[1] == 'ps' else 1, stdout=identifier if argv[1] == 'ps' else '')
        with self.assertRaises(MonitorError):
            containers.inventory(run)

    def test_new_images_are_not_starved_by_recent_failed_image(self):
        a={'image_id':'sha256:'+'a'*64, 'containers':[]}
        b={'image_id':'sha256:'+'b'*64, 'containers':[]}
        runs={containers.scope_name(a['image_id']): {'status':'error','last_attempt':utcnow(),'last_success':None}}
        self.assertEqual(containers.choose_image([a,b],runs),b)

    def test_inventory_marks_unscanned_images_as_incomplete(self):
        with TemporaryDirectory() as d, Store(d) as store:
            item={'image_id':'sha256:'+'a'*64,'containers':[{'id':'b'*64,'name':'web'}]}
            with store.db:
                store.set_meta('docker-inventory',{'observed_at':utcnow(),'images':[item]})
            result=health.evaluate(store,{**config.defaults(),'docker_monitor':True})
            docker=next(x for x in result['adapters'] if x['name']=='docker')
            self.assertEqual(docker['status'],'not_scanned')
            self.assertEqual(docker['pending'],1)

    def test_noncritical_image_baseline_does_not_spam(self):
        from test_core import row
        with TemporaryDirectory() as d, Store(d) as store:
            scope='containers:'+containers.scope_name('sha256:'+'a'*64)
            store.reconcile(scope,[row(priority='P3',target_kind='containers')],{},engine.verify_dependency)
            self.assertEqual(store.db.execute('select count(*) from outbox').fetchone()[0],0)

    def test_kev_image_baseline_still_alerts(self):
        from test_core import row
        with TemporaryDirectory() as d, Store(d) as store:
            scope='containers:'+containers.scope_name('sha256:'+'a'*64)
            store.reconcile(scope,[row(priority='P1',target_kind='containers',kev=True)],{},engine.verify_dependency)
            self.assertEqual(store.db.execute('select count(*) from outbox').fetchone()[0],1)

    def test_high_priority_image_baseline_is_not_silenced(self):
        from test_core import row
        with TemporaryDirectory() as d, Store(d) as store:
            scope='containers:'+containers.scope_name('sha256:'+'a'*64)
            store.reconcile(scope,[row(priority='P2',target_kind='containers')],{},engine.verify_dependency)
            self.assertEqual(store.db.execute('select priority from outbox').fetchone()[0],'P2')

    def test_collector_disabled_does_not_access_docker(self):
        cfg={**config.defaults(), 'docker_monitor':False}
        with patch('security_monitor.config.load',return_value=cfg), patch('security_monitor.containers.inventory',side_effect=AssertionError('unexpected Docker access')):
            self.assertEqual(containers.collect('/unused'),0)

    def test_choose_skips_recently_scanned_image(self):
        item={'image_id':'sha256:'+'a'*64,'containers':[]}
        runs={containers.scope_name(item['image_id']):{'status':'fresh','last_success':utcnow(),'last_attempt':utcnow()}}
        self.assertIsNone(containers.choose_image([item],runs))

    def test_unprivileged_worker_records_inventory_and_scans_exact_image(self):
        image='sha256:'+'a'*64
        items=[{'image_id':image,'containers':[{'id':'b'*64,'name':'web'}]}]
        with TemporaryDirectory() as d:
            path=Path(d)
            cfg={**config.defaults(),'state_dir':str(path/'state'),'docker_monitor':True}
            config.save(path/'config.json',cfg)
            (path/'inventory.json').write_text(json.dumps(items))
            with patch('security_monitor.engine.scan_targets',return_value=[{'status':'fresh'}]) as scan:
                self.assertEqual(containers.worker(path/'config.json',path/'inventory.json',image,'/tmp/image.tar'),0)
            self.assertEqual(scan.call_args.args[1]['containers'][0]['name'],containers.scope_name(image))
            self.assertEqual(scan.call_args.args[1]['containers'][0]['archive'],'/tmp/image.tar')
            with Store(path/'state') as store:
                self.assertEqual(store.meta('docker-inventory')['images'],items)

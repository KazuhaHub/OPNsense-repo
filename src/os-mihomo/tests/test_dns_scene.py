"""DNS scenes: core-only DNS presets that leave the subscription's routing and Unbound alone."""
import json
import re
import unittest
from xml.etree import ElementTree

from test_mihomo import m, SUBSCRIPTION
import test_mihomo as fixtures
import test_backup

ROOT = m.Path(m.__file__).resolve().parents[3]
PRESET = ROOT / 'share/mihomo/presets/full.yaml'
VIEW = ROOT / 'opnsense/mvc/app/views/OPNsense/Mihomo/index.volt'
SETTINGS_API = ROOT / 'opnsense/mvc/app/controllers/OPNsense/Mihomo/Api/SettingsController.php'
BACKUP_MODEL = ROOT / 'opnsense/mvc/app/models/OPNsense/Mihomo/Backup.xml'
SCENES = ('abroad', 'mainland')

# A provider that states its own DNS policy, fallback included, beside rules
# and groups a scene must leave exactly as they are.
PROVIDER = {
    'proxies': [{'name': 'CN node', 'type': 'socks5', 'server': 'cn.example.invalid', 'port': 1080},
                {'name': 'US node', 'type': 'socks5', 'server': 'us.example.invalid', 'port': 1080}],
    'proxy-groups': [{'name': 'China', 'type': 'select', 'proxies': ['CN node', 'DIRECT']},
                     {'name': 'Proxy', 'type': 'select', 'proxies': ['US node']}],
    'rules': ['GEOSITE,cn,China', 'GEOIP,CN,China', 'MATCH,Proxy'],
    'dns': {'enable': True, 'listen': ':53', 'enhanced-mode': 'fake-ip', 'ipv6': False,
            'default-nameserver': ['9.9.9.9'], 'nameserver': ['https://dns.example/dns-query'],
            'fallback': ['tls://8.8.4.4'], 'fallback-filter': {'geoip': True},
            'direct-nameserver': ['114.114.114.114'],
            'nameserver-policy': {'+.provider.example': ['10.9.9.9'], 'geosite:cn': ['114.114.114.114']}},
}


class SceneRenderTests(unittest.TestCase):
    def setUp(self):
        self.settings = {'transparent': True, 'secret': 'state-secret', 'router_dns': False,
                         'dns_scope': 'captured'}
        self.overlay = m.parse_yaml(PRESET.read_bytes())

    def render(self, scene=None, data=None, overlay=None, group=None, **kwargs):
        settings = dict(self.settings, **({} if scene is None else {
            'dns_scene': scene, 'dns_scene_group': group or ('China' if scene == 'abroad' else 'Proxy')}))
        return m.parse_yaml(m.render(PROVIDER if data is None else data, settings,
                                     overlay=self.overlay if overlay is None else overlay, **kwargs))

    def test_following_the_subscription_renders_the_same_bytes_as_before_scenes(self):
        before = m.render(PROVIDER, self.settings, overlay=self.overlay)
        self.assertEqual(before, m.render(PROVIDER, dict(self.settings, dns_scene='subscription'),
                                          overlay=self.overlay))
        self.assertEqual('subscription', m.SWITCH_DEFAULTS['dns_scene'])

    def test_a_scene_changes_dns_upstreams_only(self):
        follow = self.render()
        for scene in SCENES:
            with self.subTest(scene):
                generated = self.render(scene)
                for key in ('proxies', 'proxy-groups', 'rules'):
                    self.assertEqual(follow[key], generated[key])
                self.assertEqual({k: v for k, v in follow.items() if k != 'dns'},
                                 {k: v for k, v in generated.items() if k != 'dns'})
                dns = generated['dns']
                group = 'China' if scene == 'abroad' else 'Proxy'
                for key, value in m.scene_dns(scene, group).items():
                    self.assertEqual(value, dns[key], key)
                # Nothing of the provider's upstream policy survives beside it.
                for key in ('fallback', 'fallback-filter'):
                    self.assertNotIn(key, dns)
                self.assertNotIn('+.provider.example', dns['nameserver-policy'])
                # What is not an upstream stays as the preset and switches set it.
                self.assertEqual(follow['dns']['listen'], dns['listen'])
                self.assertEqual(follow['dns']['enhanced-mode'], dns['enhanced-mode'])
                self.assertEqual(follow['dns']['ipv6'], dns['ipv6'])

    def test_every_scene_server_is_a_literal_address_and_private_names_stay_local(self):
        for scene in SCENES:
            values = m.scene_dns(scene, 'Proxy')
            with self.subTest(scene):
                for key in ('default-nameserver', 'proxy-server-nameserver', 'direct-nameserver', 'nameserver'):
                    for server in values[key]:
                        m.ipaddress.ip_address(m.dns_server_host(server))
                for servers in values['nameserver-policy'].values():
                    for server in servers:
                        if server != 'system':
                            m.ipaddress.ip_address(m.dns_server_host(server))
                self.assertEqual(['system'], values['nameserver-policy']['geosite:private'])
                # Nothing depends on how the rules route a DNS server's address.
                self.assertFalse(values['respect-rules'])
                for server in values['default-nameserver'] + values['proxy-server-nameserver'] + values['direct-nameserver']:
                    self.assertNotIn('#', server)

    def test_each_scene_sends_its_far_side_through_the_group_and_its_near_side_direct(self):
        abroad, mainland = m.scene_dns('abroad', '🇨🇳 中国大陆'), m.scene_dns('mainland', '🚀 节点选择')
        self.assertTrue(all(server.endswith('#DIRECT') for server in abroad['nameserver']))
        self.assertTrue(all(server.endswith('#🇨🇳 中国大陆') for server in abroad['nameserver-policy']['geosite:cn']))
        self.assertTrue(all(server.endswith('#DIRECT') for server in mainland['nameserver-policy']['geosite:cn']))
        self.assertTrue(all(server.endswith('#🚀 节点选择') for server in mainland['nameserver']))
        self.assertIsNone(m.scene_dns('subscription', 'Proxy'))

    def test_a_route_the_subscription_does_not_have_is_refused_by_name(self):
        with self.assertRaisesRegex(m.Error, '"Gone"'):
            self.render('mainland', group='Gone')
        # A proxy, or DIRECT itself, is a route too.
        self.render('mainland', group='US node')
        self.render('abroad', group='DIRECT')
        for bad in ('a#b', 'a&b', 'a=b', 'a%41', 'line\nbreak', ' padded', 'x' * 129):
            with self.subTest(bad), self.assertRaises(m.Error):
                m.check_scene_group(bad)
        self.assertEqual(['China', 'Proxy'], m.proxy_groups(PROVIDER))

    def test_a_subscription_without_dns_gets_the_scene_too(self):
        data = {key: value for key, value in PROVIDER.items() if key != 'dns'}
        for scene in SCENES:
            with self.subTest(scene):
                dns = self.render(scene, data=data)['dns']
                expected = m.scene_dns(scene, 'China' if scene == 'abroad' else 'Proxy')
                self.assertEqual(expected['nameserver'], dns['nameserver'])
                self.assertEqual(expected['nameserver-policy'], dns['nameserver-policy'])

    def test_the_merge_yaml_still_wins_over_a_scene(self):
        overlay = m.merge_yaml(self.overlay, {'dns': {'nameserver': ['https://9.9.9.9/dns-query']}})
        dns = self.render('mainland', overlay=overlay)['dns']
        self.assertEqual(['https://9.9.9.9/dns-query'], dns['nameserver'])
        self.assertEqual(m.scene_dns('mainland', 'Proxy')['nameserver-policy'], dns['nameserver-policy'])

    def test_local_names_lead_the_scene_policy(self):
        names = ['internal', '168.192.in-addr.arpa']
        for scene in SCENES:
            with self.subTest(scene):
                policy = self.render(scene, local_names=names)['dns']['nameserver-policy']
                self.assertEqual(['+.internal', '+.168.192.in-addr.arpa'], list(policy)[:2])
                self.assertEqual(['127.0.0.1'], policy['+.internal'])

    def test_following_a_subscription_with_respect_rules_renders_as_before(self):
        data = dict(PROVIDER, dns=dict(PROVIDER['dns'], **{'respect-rules': True,
                                                             'proxy-server-nameserver': ['9.9.9.9']}))
        names = ['internal']
        before = m.render(data, self.settings, overlay=self.overlay, local_names=names)
        self.assertEqual(before, m.render(data, dict(self.settings, dns_scene='subscription', dns_scene_group=''),
                                          overlay=self.overlay, local_names=names))
        self.assertEqual(['127.0.0.1'], m.parse_yaml(before)['dns']['nameserver-policy']['+.internal'])

    def test_the_route_is_checked_after_the_merge_yaml(self):
        replaced = m.merge_yaml(self.overlay, {'proxy-groups': [{'name': 'Only', 'type': 'select',
                                                                 'proxies': ['US node']}]})
        with self.assertRaisesRegex(m.Error, '"Proxy"'):
            self.render('mainland', overlay=replaced)
        added = m.merge_yaml(self.overlay, {'append-proxy-groups': [{'name': 'Mine', 'type': 'select',
                                                                     'proxies': ['US node']}]})
        self.render('mainland', overlay=added, group='Mine')

    def test_a_scene_beside_the_wrong_switches_is_not_in_force(self):
        # Router DNS refuses provider fallback servers of its own accord.
        data = dict(PROVIDER, dns={k: v for k, v in PROVIDER['dns'].items() if not k.startswith('fallback')})
        for extra in ({'dns_scope': 'all'}, {'router_dns': True}, {'dns_override': True}, {'dns_scene_group': ''}):
            with self.subTest(extra):
                settings = dict(self.settings, dns_scene='mainland', dns_scene_group='Proxy')
                settings.update(extra)
                self.assertFalse(m.scene_active(settings))
                plain = {k: v for k, v in settings.items() if k not in ('dns_scene', 'dns_scene_group')}
                upstreams = 'forward-addr: 1.1.1.1@853\n' if settings.get('router_dns') else ''
                self.assertEqual(m.render(data, plain, overlay=self.overlay, upstreams=upstreams),
                                 m.render(data, settings, overlay=self.overlay, upstreams=upstreams))
        self.assertTrue(m.scene_active(dict(self.settings, dns_scene='mainland', dns_scene_group='Proxy')))


class SceneSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = fixtures.tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.system = fixtures.FakeSystem()
        self.manager = m.Manager(m.Path(self.temp.name), self.system)
        self.clock = fixtures.Clock()
        self.manager.clock = self.clock
        fixtures.DnsScopeTests.router(self, ipv6=False)
        self.manager.initialize()
        self.manager.dispatch('start')

    request = fixtures.DnsScopeTests.request
    stored = fixtures.DnsScopeTests.stored
    router = fixtures.DnsScopeTests.router

    def tick(self, seconds=5.0):
        self.clock.now += seconds
        return self.manager.watchdog_tick()

    def captured_with(self, scene):
        self.manager.apply(SUBSCRIPTION)
        self.request(dns_scope='captured', router_dns=False, dns_override=False, dns_scene=scene,
                     dns_scene_group='Proxy')
        self.manager.dispatch('enable-transparent')

    def test_a_scene_is_stored_and_rendered(self):
        self.captured_with('mainland')
        self.assertEqual('mainland', self.stored()['dns_scene'])
        dns = m.parse_yaml(self.manager.config_file.read_bytes())['dns']
        self.assertEqual(m.scene_dns('mainland', 'Proxy')['nameserver'], dns['nameserver'])
        self.assertEqual(['Proxy'], json.loads(self.manager.warnings_file.read_bytes())['proxy_groups'])
        # A post that leaves the scene out keeps it.
        self.request(geo_source='metacubex')
        self.assertEqual('mainland', self.stored()['dns_scene'])
        self.request(dns_scene='subscription')
        self.assertEqual('subscription', self.stored()['dns_scene'])

    def test_a_scene_refuses_the_switches_that_would_touch_unbound_or_its_servers(self):
        self.manager.apply(SUBSCRIPTION)
        self.request(dns_scope='captured', router_dns=False, dns_override=False)
        for values, needle in (({'dns_scope': 'all'}, 'DNS scope'), ({'dns_scope': 'off'}, 'DNS scope'),
                               ({'router_dns': True}, 'router DNS'),
                               ({'dns_override': True}, 'Override subscription DNS')):
            with self.subTest(values):
                with self.assertRaisesRegex(m.Error, needle):
                    self.request(dns_scene='abroad', dns_scene_group='Proxy', **values)
                self.assertEqual('subscription', self.stored().get('dns_scene', 'subscription'))
        with self.assertRaisesRegex(m.Error, 'DNS scene must be one of'):
            self.request(dns_scene='elsewhere', dns_scene_group='Proxy')
        with self.assertRaisesRegex(m.Error, 'needs the proxy group'):
            self.request(dns_scene='abroad')
        with self.assertRaisesRegex(m.Error, 'does not have'):
            self.request(dns_scene='abroad', dns_scene_group='Missing')
        self.assertEqual('subscription', self.stored().get('dns_scene', 'subscription'))

    def test_a_subscription_update_that_drops_the_route_is_refused_and_the_config_kept(self):
        self.captured_with('mainland')
        before = self.manager.config_file.read_bytes()
        renamed = SUBSCRIPTION.replace(b'name: Proxy', b'name: Elsewhere').replace(b'MATCH,Proxy', b'MATCH,Elsewhere')
        with self.assertRaisesRegex(m.Error, '"Proxy"'):
            self.manager.apply(renamed)
        self.assertEqual(before, self.manager.config_file.read_bytes())

    def test_settings_a_save_would_refuse_stay_readable_and_the_scene_steps_aside(self):
        # A downgrade keeps the key; the old page then changes the scope.
        self.captured_with('mainland')
        self.manager.write_settings(dict(self.manager.settings(), dns_scope='off'))
        settings = self.manager.settings()
        self.assertFalse(m.scene_active(settings))
        for action in ('status', 'restart', 'stop', 'start'):
            self.manager.dispatch(action)
        self.manager.initialize(upgrade=True)
        status = self.manager.dispatch('status')
        self.assertIn(m.SCENE_INACTIVE_NOTE, status['dns_note'])
        dns = m.parse_yaml(self.manager.config_file.read_bytes())['dns']
        self.assertNotIn('#', ' '.join(dns.get('nameserver') or []))
        # A post about something else leaves it as it is.
        self.request(geo_source='metacubex')
        self.assertEqual(('mainland', 'off'), (self.stored()['dns_scene'], self.stored()['dns_scope']))
        # The page repairs it with an ordinary save.
        self.request(dns_scope='captured')
        self.assertNotIn(m.SCENE_INACTIVE_NOTE, self.manager.dispatch('status')['dns_note'])

    def test_merge_yaml_nameservers_are_accepted_and_take_over_from_the_scene(self):
        self.captured_with('abroad')
        merge = m.parse_yaml(self.manager.merge_file.read_bytes())
        merge.setdefault('dns', {})['nameserver'] = ['https://9.9.9.9/dns-query']
        payload = self.manager.state / 'merge-request.yaml'
        payload.write_text(m.yaml.safe_dump(merge, allow_unicode=True))
        self.manager.dispatch('save-merge', str(payload))
        settings = self.manager.settings()
        self.assertTrue(settings['dns_override'])
        self.assertFalse(m.scene_active(settings))
        dns = m.parse_yaml(self.manager.config_file.read_bytes())['dns']
        self.assertEqual(['https://9.9.9.9/dns-query'], dns['nameserver'])
        self.assertIn(m.SCENE_INACTIVE_NOTE, self.manager.dispatch('status')['dns_note'])

    def test_unbound_is_never_asked_to_forward_under_a_scene(self):
        self.system.events.clear()
        self.captured_with('abroad')
        for action in ('restart', 'boot', 'start', 'restart'):
            self.manager.dispatch(action)
        self.request(dns_scene='mainland')
        self.manager.dispatch('stop')
        self.manager.dispatch('start')
        self.assertNotIn('dns-on', self.system.events)
        self.assertFalse(self.system.forwarded)
        status = self.manager.dispatch('status')
        self.assertEqual(('captured', False), (status['dns_scope'], status['dns_active']))

    def test_ipv6_reaching_captured_devices_is_noted_instead_of_answering_every_device(self):
        self.router(ipv6=True)
        self.system.events.clear()
        self.captured_with('abroad')
        self.assertNotIn('dns-on', self.system.events)
        status = self.manager.dispatch('status')
        self.assertEqual(('captured', False), (status['dns_scope'], status['dns_active']))
        self.assertIn(m.SCENE_IPV6_NOTE, status['dns_note'])
        self.assertNotIn(m.IPV6_NOTE, status['dns_note'])
        # Under DNSSEC validation the leak is the same, and so is the note.
        self.router(ipv6=True, dnssec=True)
        self.clock.now += m.IPV6_POLL
        self.assertIn(m.SCENE_IPV6_NOTE, self.manager.dispatch('status')['dns_note'])
        self.router(ipv6=True)
        # The watchdog never moves a scene to every device either.
        for _ in range(m.IPV6_CONFIRM + 3):
            self.tick(m.IPV6_POLL)
        self.assertNotIn('dns-on', self.system.events)
        self.assertEqual('captured', self.manager.dispatch('status')['dns_scope'])
        # Following the subscription keeps the earlier fallback.
        self.request(dns_scene='subscription')
        self.assertIn('dns-on', self.system.events)
        self.assertEqual('all', self.manager.dispatch('status')['dns_scope'])

    def test_a_prefix_that_arrives_after_the_start_is_noted_without_a_restart(self):
        self.captured_with('mainland')
        self.assertNotIn(m.SCENE_IPV6_NOTE, self.manager.dispatch('status')['dns_note'])
        self.router(ipv6=True)
        self.system.events.clear()
        self.clock.now += m.IPV6_POLL
        for _ in range(m.IPV6_CONFIRM + 2):
            self.tick(m.IPV6_POLL)
        self.assertIn(m.SCENE_IPV6_NOTE, self.manager.dispatch('status')['dns_note'])
        self.assertNotIn('start-transparent', self.system.events)
        self.assertNotIn('dns-on', self.system.events)
        # A status request is its own process: it reads the last look back.
        reads = self.system.address_reads
        other = m.Manager(m.Path(self.temp.name), self.system)
        other.clock = self.clock
        self.assertTrue(other.scene_ipv6(other.settings()))
        self.assertEqual(reads, self.system.address_reads)
        # And it goes away once IPv6 does.
        self.router(ipv6=False)
        self.clock.now += m.IPV6_POLL
        self.assertNotIn(m.SCENE_IPV6_NOTE, self.manager.dispatch('status')['dns_note'])

    def test_the_scene_is_mirrored_into_the_backup(self):
        self.captured_with('mainland')
        payload = self.manager._mirror_payload()
        self.assertEqual('"mainland"', payload['dns_scene'])
        self.assertEqual('"Proxy"', payload['dns_scene_group'])
        for key in ('dns_scene', 'dns_scene_group'):
            self.assertIn(key, m.BACKUP_KEYS)
            self.assertIsNotNone(ElementTree.parse(BACKUP_MODEL).find('./items/' + key))


class SceneBackupTests(unittest.TestCase):
    """The scene cases of a restore, on the backup suite's own fixture."""
    setUp = test_backup.BackupTests.setUp
    api = test_backup.BackupTests.api
    seed = test_backup.BackupTests.seed

    def test_scene_an_older_backup_drops_a_scene_its_switches_leave_out_of_force(self):
        self.seed()
        self.manager.write_settings(dict(self.manager.settings(), dns_scope='all'))
        self.assertTrue(self.manager.mirror_backup()['ok'])
        older = dict(self.store.value)
        for key in ('dns_scene', 'dns_scene_group'):
            older.pop(key, None)
        older['checksum'] = self.manager._backup_checksum(older)
        self.manager.write_settings(dict(self.manager.settings(), dns_scope='captured', dns_scene='mainland',
                                         dns_scene_group='Proxy'))
        self.store.value = older
        self.assertTrue(self.manager.restore_backup(force=True)['restored'])
        settings = self.manager.settings()
        self.assertEqual(('all', 'subscription'), (settings['dns_scope'], settings['dns_scene']))
        # One whose switches still suit the scene keeps it.
        older = dict(older, dns_scope=m.json.dumps('captured'))
        older['checksum'] = self.manager._backup_checksum(older)
        self.manager.write_settings(dict(settings, dns_scope='captured', dns_scene='abroad', dns_scene_group='Proxy'))
        self.store.value = older
        self.assertTrue(self.manager.restore_backup(force=True)['restored'])
        self.assertEqual('abroad', self.manager.settings()['dns_scene'])
        # One whose subscription lacks the route drops the scene rather than failing.
        self.manager.write_settings(dict(self.manager.settings(), dns_scene='abroad', dns_scene_group='Gone'))
        self.store.value = older
        self.assertTrue(self.manager.restore_backup(force=True)['restored'])
        self.assertEqual('subscription', self.manager.settings()['dns_scene'])


class ScenePageTests(unittest.TestCase):
    def setUp(self):
        self.view = VIEW.read_text()
        self.api = SETTINGS_API.read_text()

    def test_the_page_offers_every_scene_and_sends_the_choice(self):
        select = re.search(r'<select id="dns_scene"[^>]*>(.*?)</select>', self.view, re.S).group(1)
        self.assertEqual(sorted(m.DNS_SCENES), sorted(re.findall(r'value="([a-z]+)"', select)))
        self.assertIn("dns_scene: $('#dns_scene').val(),", self.view)
        self.assertIn("dns_scene_group: $('#dns_scene_group').val() || '',", self.view)
        self.assertIn("sceneGroups(data.proxy_groups || [], s.dns_scene_group || '');", self.view)
        self.assertIn("$('#dns_scene').val(s.dns_scene || 'subscription');", self.view)
        self.assertIn("$('#dns_scene').on('change', updateDnsControls);", self.view)

    def test_the_page_holds_the_companion_switches_while_a_scene_is_chosen(self):
        self.assertIn("$('#dns_scope').val('captured');", self.view)
        self.assertIn("$('#router_dns,#dns_override').prop('checked', false);", self.view)
        self.assertIn("$('#dns_scope').prop('disabled', scene);", self.view)
        self.assertIn('id="dns_scene_inactive"', self.view)

    def test_the_api_keeps_a_stored_scene_when_a_post_leaves_it_out(self):
        self.assertIn("if (isset($given['dns_scene'])) {\n            $payload['dns_scene'] = (string)$given['dns_scene'];",
                      self.api)
        self.assertIn("if (isset($given['dns_scene_group'])) {", self.api)
        self.assertIn("'proxy_groups' => $this->warnings('proxy_groups'),", self.api)
        self.assertNotIn('dns_scene', re.search(r'FLAGS = \[(.*?)\];', self.api, re.S).group(1))
        self.assertNotIn('dns_scene', re.search(r'CHOICES = \[(.*?)\];', self.api, re.S).group(1))


if __name__ == '__main__':
    unittest.main()

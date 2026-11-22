"""Reconstruct upstream source without accepting substituted hooks or build inputs."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    'nethub_source', Path(__file__).resolve().parents[1] / 'packaging/nethub_source.py')
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


class NetHubSourceTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.archive = Path(self.work.name) / 'synthetic-source.tar.gz'
        self.lock = {'repository': 'KazuhaHub/nethub', 'tag': 'v1.2.3', 'commit': 'a' * 40,
                     'url': 'https://github.com/KazuhaHub/nethub/releases/download/v1.2.3/source.tar.gz',
                     'sha256': '0' * 64, 'root': 'synthetic-fixture', 'plugin': adapter.PLUGIN}
        self.product = {'product_id': 'os-nethub-agent', 'product_version': '1.2.3',
                        'product_email': 'maintainer@example.com',
                        'product_website': 'https://github.com/KazuhaHub/nethub'}
        self.manifest = {'name': 'os-nethub-agent', 'version': '@VERSION@', 'abi': '@ABI@',
                         'arch': '@ARCH@', 'maintainer': 'maintainer@example.com',
                         'www': self.product['product_website'], 'licenses': ['Apache-2.0']}
        self.files = {name: b'fixed build input\n' for name in adapter.BUILD_INPUTS}
        self.files.update({adapter.PLUGIN + '/build.sh': b'VERSION=1.2.3\nexit 91\n',
            'server/.go-version': b'1.26.11\n', adapter.PLUGIN + '/frp-artifacts.json': b'{"version":"0.71.1"}',
            adapter.PLUGIN + '/FRP_VERSION': b'0.71.1\n',
            adapter.PLUGIN + '/src' + adapter.PRODUCT_PATH: json.dumps(self.product).encode(),
            adapter.PLUGIN + '/packaging/freebsd/+MANIFEST.in': json.dumps(self.manifest).encode(),
            adapter.PLUGIN + '/packaging/freebsd/pkg-descr': b'Exact source description.\n'})
        for phase, filename in adapter.HOOKS.items():
            self.files[adapter.PLUGIN + '/packaging/freebsd/' + filename] = ('#!/bin/sh\necho ' + phase + '\n').encode()

    def reconstruct(self):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, content in self.files.items():
                member = tarfile.TarInfo(self.lock['root'] + '/' + name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        self.lock['sha256'] = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        return adapter.reconstruct(self.archive, self.lock)

    def test_exact_copied_files_hooks_and_build_fingerprints_are_returned(self):
        result = self.reconstruct()
        self.assertEqual(result['files'], {adapter.PRODUCT_PATH: json.dumps(self.product).encode()})
        self.assertEqual(result['version'], '1.2.3')
        self.assertEqual(result['compiler'], 'go1.26.11')
        self.assertEqual(result['frp_version'], '0.71.1')
        self.assertEqual(set(result['build_input_sha256']), set(adapter.BUILD_INPUTS))
        for name, digest in result['build_input_sha256'].items():
            self.assertEqual(digest, hashlib.sha256(self.files[name]).hexdigest())
        for phase, filename in adapter.HOOKS.items():
            self.assertEqual(result['scripts'][phase].encode(), self.files[adapter.PLUGIN + '/packaging/freebsd/' + filename])
        self.assertFalse(result['generated_files_verified'])

    def test_first_weekly_release_uses_two_component_version(self):
        self.lock['tag'] = 'v2026.53'
        self.lock['url'] = self.lock['url'].replace('/v1.2.3/', '/v2026.53/')
        self.product['product_version'] = '2026.53'
        self.files[adapter.PLUGIN + '/build.sh'] = b'VERSION=2026.53\n'
        self.files[adapter.PLUGIN + '/src' + adapter.PRODUCT_PATH] = json.dumps(self.product).encode()
        self.assertEqual(self.reconstruct()['version'], '2026.53')

        invalid = {**self.lock, 'tag': 'v2027.53', 'url': self.lock['url'].replace('2026.53', '2027.53')}
        with self.assertRaisesRegex(ValueError, 'versioned release tag'):
            adapter.upstream.validate_lock(invalid)
        with self.assertRaisesRegex(ValueError, 'versioned release tag'):
            adapter.upstream.validate_lock({**self.lock, 'plugin': 'other/plugin'})

    def test_foreign_subtree_is_not_treated_as_nethub(self):
        self.lock['plugin'] = 'other/plugin'
        with self.assertRaisesRegex(ValueError, 'NetHub plugin subtree'):
            self.reconstruct()

    def test_missing_hook_or_build_input_is_rejected(self):
        for name in [adapter.PLUGIN + '/packaging/freebsd/+POST_INSTALL',
                     adapter.PLUGIN + '/frpc-build/go.sum', 'deploy/images/licenses.go']:
            content = self.files.pop(name)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'complete package metadata'):
                self.reconstruct()
            self.files[name] = content

    def test_source_cannot_overwrite_generated_outputs_or_leave_prefix(self):
        for path in [adapter.GENERATED.rstrip('/'), adapter.GENERATED + 'frpc',
                     adapter.GENERATED + 'frpc-licenses/LICENSE', '/etc/rc.conf']:
            name = adapter.PLUGIN + '/src' + path
            self.files[name] = b'substitution'
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.reconstruct()
            del self.files[name]

    def test_mismatched_version_identity_or_license_is_rejected(self):
        name = adapter.PLUGIN + '/src' + adapter.PRODUCT_PATH
        for mutation in [{'product_version': '9.9.9'}, {'product_id': 'os-other'}, {'product_email': ''}]:
            self.files[name] = json.dumps(dict(self.product, **mutation)).encode()
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'source identity'):
                self.reconstruct()
        self.files[name] = json.dumps(self.product).encode()
        self.manifest['licenses'] = ['MIT']
        self.files[adapter.PLUGIN + '/packaging/freebsd/+MANIFEST.in'] = json.dumps(self.manifest).encode()
        with self.assertRaisesRegex(ValueError, 'source identity'):
            self.reconstruct()

    def test_version_locks_and_empty_hooks_are_rejected(self):
        for name, content in [(adapter.PLUGIN + '/FRP_VERSION', b'9.9.9'),
                              ('server/.go-version', b'latest'),
                              (adapter.PLUGIN + '/packaging/freebsd/+PRE_INSTALL', b'\n')]:
            previous = self.files[name]
            self.files[name] = content
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.reconstruct()
            self.files[name] = previous

    def test_copytree_noise_is_ignored_without_ignoring_real_source(self):
        self.files[adapter.PLUGIN + '/src/usr/local/lib/.DS_Store'] = b'noise'
        self.files[adapter.PLUGIN + '/src/usr/local/lib/__pycache__/cached.pyc'] = b'noise'
        self.files[adapter.PLUGIN + '/src/usr/local/lib/._source.py'] = b'noise'
        self.files[adapter.PLUGIN + '/src/usr/local/lib/source.py'] = b'exact source'
        result = self.reconstruct()
        self.assertEqual(set(result['files']), {adapter.PRODUCT_PATH, '/usr/local/lib/source.py'})


if __name__ == '__main__':
    unittest.main()

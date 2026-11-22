"""Reconstruct NetHub's copied package files and hooks from a pinned archive."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re


SPEC = importlib.util.spec_from_file_location(
    'repository_upstream_source', Path(__file__).with_name('upstream_source.py'))
upstream = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upstream)

PLUGIN = 'agents/opnsense/plugin'
PRODUCT_PATH = '/usr/local/opnsense/version/nethub-agent'
GENERATED = '/usr/local/opnsense/nethub-agent/bin/'
HOOKS = {'pre-install': '+PRE_INSTALL', 'post-install': '+POST_INSTALL',
         'pre-deinstall': '+PRE_DEINSTALL', 'post-deinstall': '+POST_DEINSTALL'}
BUILD_INPUTS = [PLUGIN + '/' + name for name in (
    'build.sh', 'build.py', 'frpc_source.py', 'frp_artifact.py', 'frp-artifacts.json',
    'FRP_VERSION', 'frpc-build/go.mod', 'frpc-build/go.sum')]
BUILD_INPUTS += ['server/.go-version', 'deploy/images/licenses.go']


def json_object(raw):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError('NetHub metadata contains duplicate keys.')
            result[name] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError('NetHub metadata must be a JSON object.')
    return value


def reconstruct(archive, lock):
    """Describe copied source only; generated frpc bytes still need verification.

    This does not run the upstream builder, register a publishing record or
    claim that a compiled executable matches the source. The caller must compare
    the returned inventory and hooks with a candidate package and independently
    bind all generated files to the reviewed build-input fingerprints.
    """
    upstream.validate_lock(lock)
    if lock['repository'] != 'KazuhaHub/nethub' or lock['plugin'] != PLUGIN:
        raise ValueError('This source adapter requires the NetHub plugin subtree.')
    source = upstream.read_source(archive, lock)
    prefix = PLUGIN + '/src/'
    files = {}
    for name, content in source.items():
        if not name.startswith(prefix):
            continue
        relative = name[len(prefix):]
        parts = relative.split('/')
        # Match build.py's copytree ignore patterns, without executing it.
        if any(part in {'.DS_Store', '__pycache__'} or part.startswith('._') for part in parts):
            continue
        destination = '/' + relative
        if not destination.startswith('/usr/local/'):
            raise ValueError('NetHub copied source leaves its installation prefix.')
        if destination == GENERATED.rstrip('/') or destination.startswith(GENERATED):
            raise ValueError('Copied source collides with NetHub generated build outputs.')
        files[destination] = content
    notice_inventory = source.get(PLUGIN + '/packaging/freebsd/notice-files')
    if notice_inventory is not None:
        if notice_inventory != b'LICENSE\nNOTICE\n':
            raise ValueError('NetHub package notice inventory is invalid.')
        for name in ('LICENSE', 'NOTICE'):
            destination = '/usr/local/share/licenses/os-nethub-agent/' + name
            if destination in files or not source.get(name, b'').strip():
                raise ValueError('NetHub package notice is missing or collides with copied source.')
            files[destination] = source[name]
    if PRODUCT_PATH not in files:
        raise ValueError('NetHub source has no product version metadata.')
    product = json_object(files[PRODUCT_PATH])
    manifest_path = PLUGIN + '/packaging/freebsd/+MANIFEST.in'
    try:
        manifest = json_object(source[manifest_path])
        description = source[PLUGIN + '/packaging/freebsd/pkg-descr'].decode('utf-8').strip()
        scripts = {phase: source[PLUGIN + '/packaging/freebsd/' + name].decode('utf-8')
                   for phase, name in HOOKS.items()}
        build_inputs = {name: hashlib.sha256(source[name]).hexdigest() for name in BUILD_INPUTS}
        versions = re.findall(rb'^VERSION=([^\s]+)$', source[PLUGIN + '/build.sh'], re.M)
        compiler = source['server/.go-version'].decode('ascii').strip()
        frp = json_object(source[PLUGIN + '/frp-artifacts.json'])
        frp_version = source[PLUGIN + '/FRP_VERSION'].decode('ascii').strip()
    except (KeyError, UnicodeError) as error:
        raise ValueError('NetHub archive lacks complete package metadata or build inputs.') from error
    if len(versions) != 1 or not versions[0].isascii():
        raise ValueError('NetHub source declares no unambiguous package version.')
    version = versions[0].decode('ascii')
    if not (re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) or upstream.is_weekly_release_base(version)):
        raise ValueError('NetHub source declares no unambiguous package version.')
    if (product.get('product_id') != 'os-nethub-agent' or manifest.get('name') != 'os-nethub-agent'
            or product.get('product_version') != version or manifest.get('version') != '@VERSION@'
            or manifest.get('abi') != '@ABI@' or manifest.get('arch') != '@ARCH@'
            or not isinstance(product.get('product_email'), str) or not product['product_email']
            or product.get('product_email') != manifest.get('maintainer')
            or product.get('product_website') != 'https://github.com/KazuhaHub/nethub'
            or product.get('product_website') != manifest.get('www')
            or manifest.get('licenses') != ['Apache-2.0']):
        raise ValueError('NetHub package metadata disagrees with its source identity.')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', compiler) or frp.get('version') != frp_version:
        raise ValueError('NetHub compiler or frp version locks disagree.')
    if not description or any(not script.strip() for script in scripts.values()):
        raise ValueError('NetHub package description or lifecycle hook is empty.')
    return {'files': files, 'scripts': scripts, 'manifest_template': manifest,
            'description': description, 'version': version, 'compiler': 'go' + compiler,
            'frp_version': frp_version, 'build_input_sha256': build_inputs,
            'generated_files_verified': False}

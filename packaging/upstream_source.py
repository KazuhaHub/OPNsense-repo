"""Read a reviewed upstream release archive without executing or extracting it."""
import argparse
from contextlib import contextmanager
from datetime import date
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile


MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 20000
MAX_TAR_BYTES = MAX_SOURCE_BYTES + MAX_MEMBERS * 2048
LOCK_FIELDS = {'repository', 'tag', 'commit', 'url', 'sha256', 'root', 'plugin'}


def relative_path(value):
    """Keep tar names canonical on both the build host and verification host."""
    if (not isinstance(value, str) or not value or len(value) > 1024 or not value.isascii()
            or re.search(r'[\x00-\x20\x7f\\:]', value)
            or value.startswith('/') or PurePosixPath(value).as_posix() != value
            or any(part in {'', '.', '..'} or len(part) > 255 for part in value.split('/'))):
        raise ValueError('Upstream source path is not canonical.')
    return value


def is_weekly_release_base(value):
    """Match the first NetHub release of a UTC ISO week."""
    match = re.fullmatch(r'([1-9][0-9]{3})\.([1-9][0-9]?)', value)
    if not match:
        return False
    try:
        date.fromisocalendar(int(match[1]), int(match[2]), 1)
    except ValueError:
        return False
    return True


def validate_lock(lock):
    """A digest is required even when the release URL contains a version tag."""
    if not isinstance(lock, dict) or set(lock) != LOCK_FIELDS:
        raise ValueError('Upstream source lock has unexpected fields.')
    if not all(isinstance(value, str) for value in lock.values()):
        raise ValueError('Upstream source lock values must be strings.')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', lock['repository']):
        raise ValueError('Upstream repository must be an owner/name pair.')
    legacy_tag = re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', lock['tag'])
    nethub_week = (lock['repository'] == 'KazuhaHub/nethub' and lock['plugin'] == 'agents/opnsense/plugin'
                   and lock['tag'].startswith('v') and is_weekly_release_base(lock['tag'][1:]))
    if not (legacy_tag or nethub_week):
        raise ValueError('Upstream source requires a versioned release tag.')
    if not re.fullmatch(r'[0-9a-f]{40}', lock['commit']):
        raise ValueError('Upstream source requires a full commit pin.')
    if not re.fullmatch(r'[0-9a-f]{64}', lock['sha256']):
        raise ValueError('Upstream source requires an archive SHA256 pin.')
    prefix = 'https://github.com/' + lock['repository'] + '/releases/download/' + lock['tag'] + '/'
    if not lock['url'].startswith(prefix) or not re.fullmatch(
            r'[A-Za-z0-9][A-Za-z0-9_.-]*\.tar\.gz', lock['url'][len(prefix):]):
        raise ValueError('Upstream URL must name a release tar.gz asset.')
    if '/' in relative_path(lock['root']):
        raise ValueError('Upstream archive must have one pinned root directory.')
    relative_path(lock['plugin'])
    return lock


def load_lock(path):
    """Do not let duplicate JSON keys silently replace a reviewed pin."""
    def unique(pairs):
        value = {}
        for name, item in pairs:
            if name in value:
                raise ValueError('Upstream source lock contains a duplicate key.')
            value[name] = item
        return value

    return validate_lock(json.loads(Path(path).read_text(encoding='utf-8'), object_pairs_hook=unique))


@contextmanager
def tar_stream(raw):
    """Bound decompression before tarfile can consume oversized PAX headers."""
    with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as plain:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            total = 0
            while True:
                block = compressed.read(min(65536, MAX_TAR_BYTES - total + 1))
                if not block:
                    break
                total += len(block)
                if total > MAX_TAR_BYTES:
                    raise ValueError('Upstream archive exceeds the tar size limit.')
                plain.write(block)
        plain.seek(0)
        with tarfile.open(fileobj=plain, mode='r:') as source:
            yield source


def read_source(archive, lock):
    """Return the complete digest-bound file inventory; never trust a tar extractor.

    The caller supplies a cached archive. This function does not download assets,
    run upstream build scripts, or authorize publishing a package. The tag/commit
    relationship must be reviewed when the lock is created; a digest binds bytes,
    not the publisher's assertion that a tag names a particular commit.
    """
    validate_lock(lock)
    archive = Path(archive)
    if archive.is_symlink() or not archive.is_file():
        raise ValueError('Upstream archive must be a regular cached file.')
    with archive.open('rb') as stream:
        raw = stream.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError('Upstream archive exceeds the compressed size limit.')
    if hashlib.sha256(raw).hexdigest() != lock['sha256']:
        raise ValueError('Upstream archive differs from its SHA256 pin.')
    files, seen = {}, set()
    expanded = 0
    try:
        with tar_stream(raw) as source:
            for index, member in enumerate(source):
                if index >= MAX_MEMBERS:
                    raise ValueError('Upstream archive exceeds the member limit.')
                name = member.name
                if member.isdir() and name.endswith('/'):
                    name = name[:-1]
                relative_path(name)
                if name in seen:
                    raise ValueError('Upstream archive contains a duplicate path.')
                seen.add(name)
                if name != lock['root'] and not name.startswith(lock['root'] + '/'):
                    raise ValueError('Upstream archive leaves its pinned root.')
                if member.mode & 0o7000:
                    raise ValueError('Upstream archive contains privileged file modes.')
                if name == lock['root']:
                    if not member.isdir():
                        raise ValueError('Upstream archive root must be a directory.')
                    continue
                if (not member.isfile() and not member.isdir()) or member.issparse():
                    raise ValueError('Upstream archive contains a link or special entry.')
                if member.isdir():
                    continue
                if member.size < 0 or member.size > MAX_SOURCE_BYTES - expanded:
                    raise ValueError('Upstream archive exceeds the expanded size limit.')
                expanded += member.size
                with source.extractfile(member) as stream:
                    content = stream.read(member.size + 1)
                if len(content) != member.size:
                    raise ValueError('Upstream source member is truncated.')
                files[name] = content
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ValueError('Upstream source is not a complete gzip tar archive.') from error
    for name in seen:
        if any(parent.as_posix() in files for parent in PurePosixPath(name).parents):
            raise ValueError('Upstream archive uses a file as a directory.')
    plugin = lock['root'] + '/' + lock['plugin'] + '/'
    if not any(name.startswith(plugin) for name in files):
        raise ValueError('Upstream archive has no files in the pinned plugin subtree.')
    return {name[len(lock['root']) + 1:]: content for name, content in files.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--lock', type=Path, required=True)
    args = parser.parse_args()
    lock = load_lock(args.lock)
    files = read_source(args.archive, lock)
    print(json.dumps({'archive_sha256': lock['sha256'], 'commit': lock['commit'],
                      'files': {name: hashlib.sha256(content).hexdigest()
                                for name, content in sorted(files.items())}}, sort_keys=True))


if __name__ == '__main__':
    main()

"""
Tests for pov_fabric.

Run them with nose.
"""

from pov_fabric import *  # noqa


def test_ssh_key_matches_fingerprint():
    assert ssh_key_fingerprint(GITHUB_SSH_HOST_KEY) == GITHUB_SSH_HOST_KEY_FINGERPRINT


def test_asbool():
    assert asbool('yes')
    assert asbool('true')
    assert asbool('True')
    assert asbool('1')
    assert asbool('on')
    assert asbool(True)
    assert not asbool('off')
    assert not asbool('0')
    assert not asbool('false')
    assert not asbool('no')
    assert not asbool(False)


def test_parse_git_repo():
    r = parse_git_repo('fridge.pov.lt:git/repo.git')
    assert r.scheme == 'ssh'
    assert not r.username
    assert r.hostname == 'fridge.pov.lt'
    assert r.path == 'git/repo.git'

    r = parse_git_repo('root@fridge.pov.lt:/git/repo.git')
    assert r.scheme == 'ssh'
    assert r.username == 'root'
    assert r.hostname == 'fridge.pov.lt'
    assert r.path == '/git/repo.git'

    r = parse_git_repo('git@github.com:owner/repo')
    assert r.scheme == 'ssh'
    assert r.username == 'git'
    assert r.hostname == 'github.com'
    assert r.path == 'owner/repo'

    r = parse_git_repo('https://github.com/owner/repo')
    assert r.scheme == 'https'
    assert not r.username
    assert r.hostname == 'github.com'
    assert r.path == '/owner/repo'

    r = parse_git_repo('~/git/repo.git')
    assert r.scheme == 'file'
    assert not r.username
    assert not r.hostname
    assert r.path == '~/git/repo.git'


def test_Instance():
    instance = Instance("test", "localhost")
    assert "{name} on {host}".format(**instance) == "test on localhost"


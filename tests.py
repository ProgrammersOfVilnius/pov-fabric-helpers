# -*- coding: UTF-8 -*-
"""
Tests for pov_fabric.

Run them with nose.
"""

from cStringIO import StringIO

import mock
from nose.tools import assert_raises
from fabric.utils import _AttributeDict

from pov_fabric import (
    GITHUB_SSH_HOST_KEY,
    GITHUB_SSH_HOST_KEY_FINGERPRINT,
    GITHUB_SSH_HOST_KEY_FINGERPRINT_SHA256,
    Instance,
    _pythonify_name,
    _valid_task_name,
    asbool,
    aslist,
    get_instance,
    parse_git_repo,
    ssh_key_fingerprint,
)


def test_ssh_key_matches_fingerprint():
    assert ssh_key_fingerprint(GITHUB_SSH_HOST_KEY, force_md5=True) == GITHUB_SSH_HOST_KEY_FINGERPRINT
    assert ssh_key_fingerprint(GITHUB_SSH_HOST_KEY) in [GITHUB_SSH_HOST_KEY_FINGERPRINT,
                                                        GITHUB_SSH_HOST_KEY_FINGERPRINT_SHA256]


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


def test_aslist():
    assert aslist('') == []
    assert aslist('foo bar') == ['foo', 'bar']
    assert aslist('foo  bar') == ['foo', 'bar']
    assert aslist(['foo', 'bar']) == ['foo', 'bar']
    assert aslist(('foo', 'bar')) == ['foo', 'bar']


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


def test_Instance_asdict():
    instance = Instance("test", "localhost")
    assert instance._asdict() == {'name': 'test', 'host': 'localhost'}


def test_Instance_with_params():
    MyInstance = Instance.with_params(
        color=Instance.REQUIRED,
        shape="circle",
    )
    instance = MyInstance("test", "localhost", color="red", shape="square")
    assert instance.color == "red"
    assert instance.shape == "square"

    instance = MyInstance("test", "localhost", color="red")
    assert instance.shape == "circle"

    assert_raises(TypeError, MyInstance, "test", "localhost")
    assert_raises(TypeError, MyInstance, "test", "localhost", color="red",
                  nonsense="not allowed")


@mock.patch("sys.stderr", new_callable=StringIO)
@mock.patch("pov_fabric.env", new_callable=_AttributeDict)
def test_Instance_definition_and_management(env, stderr):
    Instance.define("test", "localhost")
    assert env.instances["test"] == Instance("test", "localhost")
    Instance.define("another", "localhost")
    assert env.instances["another"] == Instance("another", "localhost")
    Instance.define_alias('retest', 'test')
    assert_raises(SystemExit, Instance.define, "test", "again")
    assert "Instance test is already defined." in stderr.getvalue()
    assert_raises(SystemExit, Instance.define, "test.test", "localhost")
    assert "'test.test' is not a valid instance name." in stderr.getvalue()
    assert_raises(SystemExit, Instance.define_alias, "test.test", "test")
    assert "'test.test' is not a valid task name." in stderr.getvalue()

    test()  # noqa: global magically defined by Instance.define()
    assert env.instance == 'test'

    retest()  # noqa: global magically defined by Instance.define_alias()
    assert env.instance == 'test'

    env.command = 'triangulate'
    assert get_instance() == Instance("test", "localhost")
    assert get_instance("another") == Instance("another", "localhost")
    assert_raises(SystemExit, get_instance, "nonesuch")
    assert "Please specify an instance (another, test), e.g.\n\n  fab another triangulate" in stderr.getvalue()

    del env['instances']
    assert_raises(SystemExit, get_instance, "test")
    assert "There are no instances defined in env.instances" in stderr.getvalue()


@mock.patch("sys.stderr", new_callable=StringIO)
@mock.patch("pov_fabric.env", new_callable=_AttributeDict)
def test_Instance_definition_with_names_that_are_not_valid_Python_identifiers(env, stderr):
    Instance.define("ą", "a.example.com")
    Instance.define("č", "c.example.com")

    __()  # noqa: global magically defined by Instance.define()
    assert env.instance == 'ą'

    ___()  # noqa: global magically defined by Instance.define()
    assert env.instance == 'č'


def test_valid_task_name():
    assert _valid_task_name('foo')
    assert _valid_task_name('foo-bar')
    assert _valid_task_name('foo_bar')
    assert not _valid_task_name('')
    assert not _valid_task_name('foo:bar')
    assert not _valid_task_name('-foo')
    assert not _valid_task_name('foo bar')
    assert not _valid_task_name('foo.bar')

def test_pythonify_name():
    assert _pythonify_name('foo') == 'foo'
    assert _pythonify_name('foo-bar') == 'foo_bar'
    assert _pythonify_name('foo.bar') == 'foo_bar'
    assert _pythonify_name('foo_123') == 'foo_123'
    assert _pythonify_name('123') == '_123'
    assert _pythonify_name('ą') == '__'

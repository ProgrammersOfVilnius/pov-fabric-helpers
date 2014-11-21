"""
Fabric helpers
"""

import posixpath
import subprocess
import sys
import tempfile
import urlparse
from pipes import quote  # TBD: use shlex.quote on Python 3.2+

from fabric.api import run, sudo, quiet, settings, cd, env, abort, task, with_settings
from fabric.contrib.files import exists, append


#
# Constants
#

# Produced by 'ssh-keyscan github.com'
GITHUB_SSH_HOST_KEY = "github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="

# Fingerprint from https://help.github.com/articles/what-are-github-s-ssh-key-fingerprints/
GITHUB_SSH_HOST_KEY_FINGERPRINT = "16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48"

# Known SSH host keys to be added to ~/.ssh/known_hosts if needed
KNOWN_HOSTS = {
    "github.com": GITHUB_SSH_HOST_KEY,
}


#
# Command-line parsing
#

def asbool(v):
    """Convert value to boolean."""
    if isinstance(v, basestring):
        return v.lower() in ('yes', 'true', 'on', '1')
    else:
        return bool(v)


#
# System management helpers
#

def ensure_apt_not_outdated():
    """Make sure apt-get update was run within the last day."""
    if not run("find /var/lib/apt/lists -maxdepth 0 -mtime -1", quiet=True):
        sudo("apt-get update -qq")


def package_installed(package):
    """Check if the specified packages is installed."""
    # XXX: doing this in a loop is slow :(
    with quiet():
        status = run("dpkg-query -W --showformat='${Status}' %s" % package)
        return status == "install ok installed"


def install_packages(*packages, **kw):
    """Install system packages.

    You can use any of these styles::

        install_packages('foo bar')
        install_packages('foo', 'bar')
        install_packages(['foo', 'bar'])

    Keyword arguments:

    - ``missing_only`` (default: False) -- apt-get install only the missing
      packages.  This can be slower than just letting apt figure it out.

    - ``interactive`` (default: False) -- allow interactive prompts during
      package installation.

    """
    missing_only = kw.pop('missing_only', True)
    interactive = kw.pop('interactive', False)
    if kw:
        raise TypeError('unexpected keyword arguments: {}'
                        .format(', '.join(sorted(kw))))
    if len(packages) == 1 and not isinstance(packages[0], str):
        # handle lists and tuples
        packages = packages[0]
    if missing_only:
        packages = [p for p in packages if not package_installed(p)]
    if not packages:
        return
    ensure_apt_not_outdated()
    command = "apt-get install -qq -y %s" % " ".join(packages)
    if not interactive:
        command = "DEBIAN_FRONTEND=noninteractive " + command
    sudo(command)


def ssh_key_fingerprint(host_key):
    """Compute the fingerprint of a public key."""
    if not host_key.startswith('ssh-'):
        host_key = host_key.split(None, 1)[1]
    with tempfile.NamedTemporaryFile(prefix='pov-fabric-') as f:
        f.write(host_key)
        f.flush()
        output = subprocess.check_output(['ssh-keygen', '-l', '-f', f.name])
        # Example output:
        # "2048 16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48 /tmp/github_rsa.pub (RSA)\n"
    return output.split()[1]


def ensure_known_host(host_key, known_hosts='/root/.ssh/known_hosts'):
    """Make sure a host key exists in the known_hosts file.

    This is idempotent: running it again won't add the same key again.
    """
    if not exists(known_hosts, use_sudo=True):
        if not exists(posixpath.dirname(known_hosts), use_sudo=True):
            sudo('install -d -m700 %s' % posixpath.dirname(known_hosts))
        sudo('touch %s' % known_hosts)
    # Must use shell=True to work around Fabric bug, where it would fall
    # flat in contains() with an error ("sudo: export: command not
    # found") that is silently suppressed, resulting in always appending
    # the ssh key to /root/.ssh/known_hosts.  Probably because I use
    # `with shell_env(LC_ALL='C.UTF-8'):`.
    append(known_hosts, host_key, use_sudo=True, shell=True)


def ensure_user(user):
    """Create a system user if it doesn't exist already.

    This is idempotent: running it again won't add the same user again.
    """
    with quiet():
        if run("id {user}".format(user=user)).succeeded:
            return
    with settings(sudo_user="root"):
        sudo("adduser --system --group --disabled-password --quiet %s" % user)


def ensure_locales(*languages):
    """Make sure locales are generated.

    Example::

        ensure_locales('en', 'lt')

    """
    for language in languages:
        sudo("locale-gen --no-purge {language}".format(language=language))


#
# Git
#

def parse_git_repo(git_repo):
    """Parse a git repository URL.

    git-clone(1) lists these as examples of supported URLs:

    - ssh://[user@]host.xz[:port]/path/to/repo.git/
    - git://host.xz[:port]/path/to/repo.git/
    - http[s]://host.xz[:port]/path/to/repo.git/
    - ftp[s]://host.xz[:port]/path/to/repo.git/
    - rsync://host.xz/path/to/repo.git/
    - [user@]host.xz:path/to/repo.git/
    - ssh://[user@]host.xz[:port]/~[user]/path/to/repo.git/
    - git://host.xz[:port]/~[user]/path/to/repo.git/
    - [user@]host.xz:/~[user]/path/to/repo.git/
    - /path/to/repo.git/
    - file:///path/to/repo.git/

    This function doesn't support the <transport>::<address> syntax, and it
    doesn't understand insteadOf shortcuts from ~/.gitconfig.
    """
    if '://' in git_repo:
        return urlparse.urlparse(git_repo)
    if ':' in git_repo:
        netloc, colon, path = git_repo.partition(':')
        return urlparse.ParseResult('ssh', netloc, path, '', '', '')
    else:
        return urlparse.ParseResult('file', '', git_repo, '', '', '')


@with_settings(sudo_user='root')
def git_clone(git_repo, work_dir, branch='master', force=False):
    """Clone a specified branch of the git repository into work_dir.

    If work_dir exists and force is False (default), aborts.

    If work_dir exists and force is True, performs a 'git fetch' followed by
    'git reset --hard origin/{branch}'.

    Takes care to allow SSH agent forwarding to be used for authentication,
    if you use SSH.

    Takes care to add the SSH host key to /root/.ssh/known_hosts, if you're
    cloning from a host in KNOWN_HOSTS.

    Returns the commit hash of the version cloned.
    """
    env = {}
    url = parse_git_repo(git_repo)
    if url.scheme == 'ssh':
        host_key = KNOWN_HOSTS.get(url.hostname)
        if host_key:
            ensure_known_host(host_key)
        # sudo removes SSH_AUTH_SOCK from the environment, so we can't make use
        # of the ssh agent forwarding unless we cunningly preserve the envvar
        # and sudo to root (because only root and the original user will be
        # able to access the socket)
        env['SSH_AUTH_SOCK'] = run("echo $SSH_AUTH_SOCK", quiet=True)
    if exists(posixpath.join(work_dir, '.git')) and force:
        with cd(work_dir):
            with settings(shell_env=env):
                sudo("git fetch")
            sudo("git reset --hard origin/{branch}".format(branch=branch))
    else:
        with settings(shell_env=env):
            sudo("git clone -b {branch} {git_repo} {work_dir}".format(
                branch=branch,
                git_repo=git_repo,
                work_dir=work_dir))
    with cd(work_dir):
        got_commit = sudo("git describe --always --dirty", quiet=True).strip()
    return got_commit


@with_settings(sudo_user='root')
def git_update(work_dir, branch='master', force=False):
    """Update a specified git checkout.

    Aborts if the checkout cannot be fast-forwarded to the specified branch,
    unless force is specified.

    Discards all local changes (committed or not) if force is True, so use with
    care!

    Returns the commit hash of the version fetched.
    """
    env = {}
    env['SSH_AUTH_SOCK'] = run("echo $SSH_AUTH_SOCK", quiet=True)
    with cd(work_dir):
        with settings(shell_env=env):
            sudo("git fetch")
        if force:
            sudo("git reset --hard origin/{branch}".format(branch=branch))
        else:
            sudo("git merge --ff-only origin/{branch}".format(branch=branch))
        got_commit = sudo("git describe --always --dirty", quiet=True).strip()
    return got_commit


#
# PostgreSQL helper
#

def postgresql_user_exists(user):
    """Check if a postgresql user already exists."""
    out = sudo("psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname = '%s'\"" % user,
               user='postgres', quiet=True)
    return bool(out)


def ensure_postgresql_user(user):
    """Create a PostgreSQL user if it doesn't exist already.

    This is idempotent: running it again won't add the same user again.
    """
    if not postgresql_user_exists(user):
        sudo("LC_ALL=C.UTF-8 createuser -DRS %s" % user, user='postgres')


def postgresql_db_exists(dbname):
    """Check if a PostgreSQL database already exists."""
    out = sudo("psql -tAc \"SELECT 1 FROM pg_database WHERE datname = '%s'\"" % dbname,
               user='postgres', quiet=True)
    return bool(out)


def ensure_postgresql_db(dbname, owner):
    """Create a PostgreSQL database if it doesn't exist already.

    This is idempotent: running it again won't create the database again.
    """
    if not postgresql_db_exists(dbname):
        sudo("LC_ALL=C.UTF-8 createdb -E utf-8 -T template0 -O %s %s" % (owner, dbname),
             user='postgres')


#
# pov-admin-tools
#

def changelog(message, context=None, append=False, optional=True):
    """Append a message to /root/Changelog, with a timestamped header.

    Depends on pov-admin-tools.  If it's not installed, skips the
    message (unless you say optional=False, in which case it aborts
    with an error).

    By default the message gets a timestamped header.  Use append=True
    to append to an existing message instead of starting a new one.

    If context is given, message will be formatted using given context
    (``message = message.format(**context)``).
    """
    if exists('/usr/sbin/new-changelog-entry') or not optional:
        cmd = 'new-changelog-entry'
        if append:
            cmd += ' -a'
        if context is not None:
            message = message.format(**context)
        cmd += ' ' + quote(message)
        sudo(cmd, user='root')


def changelog_append(message, context=None):
    """Append a message to /root/Changelog.

    Shortcut for changelog(message, append=True).
    """
    changelog(message, context, append=True)


#
# Instance management
#


class Instance(object):
    """Service instance configuration.

    Subclass to add more parameters, e.g. ::

        from pov_fabric import Instance as BaseInstance

        class Instance(BaseInstance):
            def __init__(self, name, host, home='/opt/project'):
                super(Instance, self).Instance.__init__(name, host)
                self.home = home

    Or use the ``with_params()`` classmethod.
    """

    def __init__(self, name, host, **kwargs):
        self.name = name
        self.host = host
        self.__dict__.update(kwargs)

    def _asdict(self):
        """Return the instance parameters as a dict.

        Useful for string formatting, e.g. ::

            print('{name} is on {host}'.format(**instance._asdict()))

        Mimics the API of ``collections.namedtuple``.
        """
        return self.__dict__

    REQUIRED = object()

    @classmethod
    def with_params(cls, **params):
        """Define an instance subclass

        Usage example::

            from pov_fabric import Instance

            Instance = Instance.with_params(
                required_arg1=Instance.REQUIRED,
                optional_arg1='default value',
                optional_arg2=None)

        """

        def __init__(self, name, host, **kw):
            super(new_cls, self).__init__(name, host)
            for k, v in params.items():
                if v is cls.REQUIRED and k not in kw:
                    raise TypeError(
                        "__init__() requires a keyword argument '{}'"
                        .format(k))
                setattr(self, k, v)
            for k, v in kw.items():
                if k not in params:
                    raise TypeError(
                        "__init__() got an unexpected keyword argument '{}'"
                        .format(k))
                setattr(self, k, v)
        new_cls = type('Instance', (cls, ), dict(__init__=__init__))
        return new_cls

    @classmethod
    def define(cls, *args, **kwargs):
        """Define an instance.

        Creates a new Instance object with the given constructor arguments,
        registers it in env.instances and defines an instance selector task.
        """
        instance = cls(*args, **kwargs)
        _define_instance(instance)
        _define_instance_task(instance.name, stacklevel=2)


def _define_instance(instance):
    """Define an instance.

    Instances are stored in the ``env.instances`` dictionary, which is created
    on demand.
    """
    if not hasattr(env, 'instances'):
        env.instances = {}
    if instance.name in env.instances:
        abort("Instance {name} is already defined.".format(name=instance.name))
    env.instances[instance.name] = instance


def _define_instance_task(name, stacklevel=1):
    """Define an instance task

    This task will set env.instance to the name of the task.
    """
    def fn():
        env.instance = name
    fn.__doc__ = """Select instance '%s' for subsequent tasks.""" % name
    instance_task = task(name=name)(fn)
    sys._getframe(stacklevel).f_globals[name.replace('-', '_')] = instance_task


def get_instance(instance_name=None):
    """Select the instance to operate on.

    Defaults to env.instance if instance_name is not specified.

    Aborts with a help message if the instance is not defined.
    """
    instances = sorted(getattr(env, 'instances', {}))
    if not instances:
        abort("There are no instances defined in env.instances.")
    if not instance_name:
        instance_name = getattr(env, 'instance', None)
    try:
        return env.instances[instance_name]
    except KeyError:
        abort("Please specify an instance ({known_instances}), e.g.\n\n"
              "  fab {instance} {command}".format(
                  known_instances=", ".join(instances),
                  instance=instances[0],
                  command=env.command))

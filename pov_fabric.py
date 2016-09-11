"""
Fabric helpers
"""

import hashlib
import os
import posixpath
import subprocess
import string
import sys
import tempfile
import textwrap
import urlparse
from StringIO import StringIO
from contextlib import closing
from pipes import quote  # TBD: use shlex.quote on Python 3.2+

from fabric.api import (
    run, sudo, quiet, settings, cd, env, abort, task, with_settings,
)
from fabric.contrib.files import exists, append
from fabric.utils import apply_lcwd
from fabric.sftp import SFTP


#
# Constants
#

# Produced by 'ssh-keyscan github.com'
GITHUB_SSH_HOST_KEY = "github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="

# Fingerprint from https://help.github.com/articles/what-are-github-s-ssh-key-fingerprints/
GITHUB_SSH_HOST_KEY_FINGERPRINT = "16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48"
GITHUB_SSH_HOST_KEY_FINGERPRINT_SHA256 = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"

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


def aslist(v):
    """Convert value to list."""
    if isinstance(v, basestring):
        return v.split()
    else:
        return list(v)


#
# System management helpers
#

def assert_shell_safe(*args, **kw):
    """Check that each argument can be passed to shell safely.

    This is ultra-paranoid mode: only a small set of whitelisted characters are
    allowed.  No spaces, no leading dashes, no glob wildcards, no quotes, no
    backticks, no dollar signs, no history expansion, no brace expansion.

    Tilde expansion is allowed.

    It might be too strict.  Therefore you can supply a keyword-only argument
    ``extra_allow`` that lists additional characters to be allowed.
    """
    extra_allow = kw.pop('extra_allow', '')
    if kw:
        raise TypeError('unexpected keyword arguments: {}'
                        .format(', '.join(sorted(kw))))
    allowed_chars = set(string.letters + string.digits + '/-._~')
    allowed_chars.update(extra_allow)
    for arg in args:
        if not set(arg) <= allowed_chars or arg.startswith('-'):
            raise ValueError('{} is not safe for shell'.format(arg))


def ensure_apt_not_outdated():
    """Make sure apt-get update was run within the last day."""
    if not run("find /var/lib/apt/lists -maxdepth 0 -mtime -1", quiet=True):
        sudo("apt-get update -qq")


def package_available(package):
    """See if a package is available for installation."""
    assert_shell_safe(package)
    with quiet():
        output = run('apt-cache madison {}'.format(package))
    # The terrible: apt-cache always returns status code 0 and never prints
    # to stderr, no matter if the package is or isn't available.  The error
    # message is translated.  If the package is available, the output is
    # a multi-line list with |-separated columns that contain package
    # names, versions, and the repository info.
    return '|' in output


def package_installed(package):
    """Check if the specified packages is installed."""
    assert_shell_safe(package)
    # XXX: doing this in a loop is slow :(
    with quiet():
        # XXX idea: return exists('/var/lib/dpkg/info/{}.list'.format(package))
        # caveats: libnss-myhostname:amd64.list :/
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

    - ``changelog`` (default: False) -- record installed packages in
      /root/Changelog

    """
    missing_only = kw.pop('missing_only', False)
    interactive = kw.pop('interactive', False)
    changelog = kw.pop('changelog', False)
    if kw:
        raise TypeError('unexpected keyword arguments: {}'
                        .format(', '.join(sorted(kw))))
    if len(packages) == 1 and not isinstance(packages[0], str):
        # handle lists and tuples
        packages = packages[0]
    packages = " ".join(packages).split()
    if missing_only:
        packages = [p for p in packages if not package_installed(p)]
    if not packages:
        return
    ensure_apt_not_outdated()
    for package in packages:
        assert_shell_safe(package)
    command = "apt-get install -qq -y %s" % " ".join(packages)
    if not interactive:
        command = "DEBIAN_FRONTEND=noninteractive " + command
    if changelog:
        changelog_append("apt-get install %s" % " ".join(packages))
    sudo(command)


def install_missing_packages(*packages, **kw):
    """Install missing system packages.

    Alias for install_packages(*packages, missing_only=True, **kw).
    """
    kw.setdefault('missing_only', True)
    install_packages(*packages, **kw)


def ssh_key_fingerprint(host_key, force_md5=False):
    """Compute the fingerprint of a public key.

    Can return a SHA256 or an MD5 fignerprint, depending on your OpenSSH
    version.  You can insist on MD5 if you want.
    """
    if not host_key.startswith('ssh-'):
        host_key = host_key.split(None, 1)[1]
    with tempfile.NamedTemporaryFile(prefix='pov-fabric-') as f:
        f.write(host_key)
        f.flush()
        output = subprocess.check_output(['ssh-keygen', '-l', '-f', f.name])
        # Example output (old ssh):
        # "2048 16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48 /tmp/github_rsa.pub (RSA)\n"
        # Example output (new ssh):
        # "2048 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 no comment (RSA)\n"
        # Example output (new ssh with -E md5):
        # "2048 MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48 no comment (RSA)\n"
        fingerprint = output.split()[1]
        if fingerprint.startswith('SHA256') and force_md5:
            # we want MD5 still, for backwards-compat, but we should stop doing
            # that eventually
            output = subprocess.check_output(['ssh-keygen', '-l', '-f', f.name,
                                              '-E', 'md5'])
        fingerprint = output.split()[1].replace('MD5:', '')
    return fingerprint


def register_host_key(host_key, fingerprint=None, fingerprints=None, force_md5=False):
    """Register a known host key.

    This will be used by git_clone() and such to add the host key automatically
    if you're cloning from the host.
    """
    if fingerprint is not None:
        if fingerprints is not None:
            raise ValueError('Please provide either fingerprint or fingerprints, but not both')
        fingerprints = [fingerprint]
        force_md5 = True
    hostname = host_key.split()[0]
    if hostname in KNOWN_HOSTS and KNOWN_HOSTS[hostname] != host_key:
        abort("There's a different host key already registered for {}".format(hostname))
    if fingerprint:
        if ssh_key_fingerprint(host_key, force_md5=force_md5) not in fingerprints:
            abort("SSH host key doesn't match fingerprint")
    KNOWN_HOSTS[hostname] = host_key


def ensure_known_host(host_key, known_hosts='/root/.ssh/known_hosts'):
    """Make sure a host key exists in the known_hosts file.

    This is idempotent: running it again won't add the same key again.
    """
    assert_shell_safe(known_hosts)
    if not exists(known_hosts, use_sudo=True):
        ensure_directory(posixpath.dirname(known_hosts), mode=0o700)
        sudo('touch %s' % known_hosts)
    # Must use shell=True to work around Fabric bug, where it would fall
    # flat in contains() with an error ("sudo: export: command not
    # found") that is silently suppressed, resulting in always appending
    # the ssh key to /root/.ssh/known_hosts.  Probably because I use
    # `with shell_env(LC_ALL='C.UTF-8'):`.
    append(known_hosts, host_key, use_sudo=True, shell=True)


def ensure_user(user, shell=None, home=None, changelog=False, create_home=True):
    """Create a system user if it doesn't exist already.

    This is idempotent: running it again won't add the same user again.
    """
    assert_shell_safe(user, shell or '', home or '')
    with quiet():
        if run("id {user}".format(user=user)).succeeded:
            # XXX: check if shell matches what we asked, and run chsh if not?
            return
    doit = run_and_changelog if changelog else sudo
    with settings(sudo_user="root"):
        command = ['adduser --quiet --system --group --disabled-password']
        if shell:
            command.append('--shell={}'.format(shell))
        if home:
            command.append('--home={}'.format(home))
        if not create_home:
            command.append('--no-create-home')
        command.append(user)
        doit(" ".join(command))


def ensure_locales(*languages):
    """Make sure locales are generated.

    Example::

        ensure_locales('en', 'lt')

    """
    assert_shell_safe(*languages)
    supported_locales = run("locale -a", quiet=True).splitlines()
    # as a shortcut we'll assume that if one xx_... locale is supported
    # then all of them are supported
    supported_languages = set(locale.partition('.')[0].partition('_')[0]
                              for locale in supported_locales)
    for language in languages:
        if language not in supported_languages:
            sudo("locale-gen {language}".format(language=language))


def ensure_directory(pathname, mode=None):
    """Make sure directory exists.

    Returns True if it had to create the directory, False if the directory
    already existed.
    """
    if isinstance(mode, int):
        mode = '{:o}'.format(mode)
    assert_shell_safe(pathname, mode or '')
    if not exists(pathname, use_sudo=True):
        command = ['install -d']
        if mode:
            command.append('-m{}'.format(mode))
        command.append(pathname)
        sudo(' '.join(command))
        return True
    else:
        return False


def upload_file(local_file, remote_path, mode=0o644, owner="root:root",
                temp_dir="", changelog=False):
    """Upload a file to a remote host.

    ``local_file`` can be a filename or a seekable file-like object.  Globbing
    is not supported.

    ``remote_file`` should be a full filename, not just the directory.

    ``mode`` can be an integer (e.g. 0o755).

    ``changelog``, if True, adds a changelog message of the form "uploaded
    {filename}".

    Bug: doesn't handle ``with cd(...):`` or ``with lcd(...):``.  Probably.

    Bug: doesn't set mode/ownership if the file exists and has the same content
    but different mode/ownership.

    Warning: is not suitable for uploading secrets (changes the mode after
    uploading the file), unless you take care to specify ``temp_dir`` to point
    to a non-world-readable area.

    Undocumented features that are subject to change without notice:
    ``mode`` can be a string or None; ``owner`` can be None.
    """
    if isinstance(mode, int):
        mode = '{:o}'.format(mode)
    assert_shell_safe(remote_path, mode or '', temp_dir)
    assert_shell_safe(owner or '', extra_allow=':')
    local_is_path = not callable(getattr(local_file, 'read', None))
    if isinstance(local_file, StringIO) and not getattr(local_file, 'name', None):
        local_file.name = os.path.basename(remote_path)
    with closing(SFTP(env.host_string)) as ftp:
        if env.get('cwd'):
            home = ftp.normalize('.')
            temp_dir = posixpath.join(home, temp_dir)
        tmp_path = posixpath.join(
            temp_dir, hashlib.sha1(env.host_string + remote_path).hexdigest())
        assert_shell_safe(tmp_path)
        ftp.put(local_file, tmp_path, use_sudo=False, mirror_local_mode=False,
                mode=None, local_is_path=local_is_path, temp_dir="")
        with quiet():
            same = sudo("test -f {realfile} && cmp -s {tempfile} {realfile}".format(
                tempfile=tmp_path, realfile=remote_path)).succeeded
        if same:
            sudo("rm {tempfile}".format(tempfile=tmp_path))
            return False
        else:
            if mode is not None:
                sudo('chmod {mode} {tempfile}'.format(mode=mode, tempfile=tmp_path))
            if owner:
                sudo('chown {owner} {tempfile}'.format(owner=owner, tempfile=tmp_path))
            sudo("mv {tempfile} {realfile}".format(tempfile=tmp_path,
                                                   realfile=remote_path))
            if changelog:
                changelog_append("# updated {}".format(remote_path))
            return True


def render_jinja2(template_filename, context, template_dir=None):
    """Render a Jinja2 template.

    Based on fabric.contrib.files.upload_template.

    Differences: adds back the trailing newline that Jinja2 eats for some
    reason.
    """
    from jinja2 import Environment, FileSystemLoader
    template_dir = template_dir or os.getcwd()
    template_dir = apply_lcwd(template_dir, env)
    jenv = Environment(loader=FileSystemLoader(template_dir))
    text = jenv.get_template(template_filename).render(**context or {})
    return text.encode('UTF-8') + '\n'


def render_sinterp(filename, context=None, template_dir=None):
    """Render a Python 2 string template.

    Based on fabric.contrib.files.upload_template.
    """
    if template_dir:
        filename = os.path.join(template_dir, filename)
    filename = apply_lcwd(filename, env)
    with open(os.path.expanduser(filename)) as inputfile:
        text = inputfile.read()
    if context:
        text = text % context
    return text


def generate_file(template, filename, context=None, use_jinja=False,
                  mode=0o644, owner="root:root", changelog_append=True):
    """Generate a file from a template

    Generates ``filename`` on the remote server using ``template`` as a source.
    The syntax depends on ``use_jinja``: either Jinja2 (if True) or Python's
    builtin string formatting (of the older, ``%(name)s`` variety).
    ``context`` should be a dict containing variables for interpolation.

    Changes the file ownership and mode.

    Creates the parent directory automatically if it doesn't exist (owned by
    root, mode 0755).

    If ``changelog_append`` is True, calls changelog_append() to note that
    ``filename`` was generated.

    Returns True if it had to replace the file, False if the file already
    existed with the right content.
    """
    assert_shell_safe(filename)
    ensure_directory(posixpath.dirname(filename))
    if use_jinja:
        text = render_jinja2(template, context)
    else:
        text = render_sinterp(template, context)
    if upload_file(StringIO(text), filename, mode=mode, owner=owner):
        changelog('# generated {filename}'.format(filename=filename),
                  append=changelog_append)
        return True
    else:
        return False


def download_file(filename, url):
    """Download a file from a given URL."""
    assert_shell_safe(filename)
    assert_shell_safe(url, extra_allow=':')
    run_and_changelog('wget {url} -O {filename}'.format(url=url, filename=filename))


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
def git_clone(git_repo, work_dir, branch='master', force=False,
              changelog=False):
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
    assert_shell_safe(git_repo, extra_allow='@:')
    assert_shell_safe(work_dir, branch)
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
    if exists(posixpath.join(work_dir, '.git')):
        return git_update(work_dir, branch=branch, force=force,
                          changelog=changelog, verify_remote_url=git_repo)
    doit = run_and_changelog if changelog else sudo
    with settings(shell_env=env):
        doit("git clone -b {branch} {git_repo} {work_dir}".format(
            branch=branch,
            git_repo=git_repo,
            work_dir=work_dir))
    with cd(work_dir):
        got_commit = sudo("git describe --always --dirty", quiet=True).strip()
    if changelog:
        changelog_append('# got commit {sha}'.format(sha=got_commit))
    return got_commit


@with_settings(sudo_user='root')
def git_update(work_dir, branch='master', force=False, changelog=False,
               verify_remote_url=None):
    """Update a specified git checkout.

    Aborts if the checkout cannot be fast-forwarded to the specified branch,
    unless force is specified.

    Discards all local changes (committed or not) if force is True, so use with
    care!

    Returns the commit hash of the version fetched.
    """
    assert_shell_safe(work_dir, branch)
    env = {}
    with cd(work_dir):
        with quiet():
            tracking_branch = run("git rev-parse --symbolic-full-name 'HEAD@{u}'")
        if not tracking_branch.startswith("refs/remotes/origin/"):
            abort("{} is not tracking a branch from remote 'origin'".format(work_dir))
        tracking_branch = tracking_branch[len("refs/remotes/origin/"):]
        if force and tracking_branch != branch:
            changelog_append('cd {work_dir} && git checkout {branch}'.format(
                work_dir=work_dir, branch=branch))
            sudo("git checkout {branch}".format(branch=branch))
            with quiet():
                tracking_branch = run("git rev-parse --symbolic-full-name 'HEAD@{u}'")
            if not tracking_branch.startswith("refs/remotes/origin/"):
                abort("{} is not tracking a branch from remote 'origin'".format(work_dir))
            tracking_branch = tracking_branch[len("refs/remotes/origin/"):]
        if tracking_branch != branch:
            abort("{} is not tracking branch {} (it's tracking {})".format(
                work_dir, branch, tracking_branch))
        git_repo = run("git config --get remote.origin.url", quiet=True)
        if verify_remote_url and git_repo != verify_remote_url:
            abort("{} is not tracking the right remote {} (it's tracking {})".format(
                work_dir, verify_remote_url, git_repo))
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
    with cd(work_dir):
        with settings(shell_env=env):
            sudo("git fetch")
        old_commit = sudo("git describe --always --dirty", quiet=True).strip()
        if force:
            changelog_append('cd {work_dir}\n  git fetch && git reset --hard origin/{branch}'.format(
                work_dir=work_dir, branch=branch))
            sudo("git reset --hard origin/{branch}".format(branch=branch))
        else:
            changelog_append('cd {work_dir}\n  git pull --ff-only'.format(work_dir=work_dir))
            sudo("git merge --ff-only origin/{branch}".format(branch=branch))
        got_commit = sudo("git describe --always --dirty", quiet=True).strip()
    if changelog:
        if old_commit == got_commit:
            changelog_append('  # no changes')
        else:
            changelog_append('  # update {oldsha}..{sha}'.format(oldsha=old_commit, sha=got_commit))
    return got_commit


#
# PostgreSQL helper
#

def postgresql_user_exists(user):
    """Check if a postgresql user already exists."""
    assert_shell_safe(user)
    out = sudo("psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname = '%s'\"" % user,
               user='postgres', quiet=True)
    return bool(out)


def ensure_postgresql_user(user):
    """Create a PostgreSQL user if it doesn't exist already.

    This is idempotent: running it again won't add the same user again.
    """
    assert_shell_safe(user)
    if not postgresql_user_exists(user):
        sudo("LC_ALL=C.UTF-8 createuser -DRS %s" % user, user='postgres')


def postgresql_db_exists(dbname):
    """Check if a PostgreSQL database already exists."""
    assert_shell_safe(dbname)
    out = sudo("psql -tAc \"SELECT 1 FROM pg_database WHERE datname = '%s'\"" % dbname,
               user='postgres', quiet=True)
    return bool(out)


def ensure_postgresql_db(dbname, owner):
    """Create a PostgreSQL database if it doesn't exist already.

    This is idempotent: running it again won't create the database again.
    """
    assert_shell_safe(dbname)
    if not postgresql_db_exists(dbname):
        sudo("LC_ALL=C.UTF-8 createdb -E utf-8 -l en_US.UTF-8 -T template0 -O %s %s" % (owner, dbname),
             user='postgres')


#
# Apache
#

def install_apache_website(apache_conf_template, domain, context=None,
                           use_jinja=False, modules=[], reload_apache=True):
    """Upload Apache config for a website and enable it.

    Takes care of
    - generating an apache config file template from ``apache_conf_template``
    - uploading it to /etc/apache2/sites-available/{domain}.conf
    - file permissions and ownership (0644, root:root)
    - creating a directory for logs (/var/log/apache2/{domain})
    - enabling the website with a2ensite
    - reloading apache

    Caveats:
    - assumes the Apache template configures logs in /var/log/apache2/{domain}
    - assumes any other files (such as SSL certificates and keys) required for
      the Apache config to work are already uploaded
    """
    modules = aslist(modules)
    changed = generate_file(apache_conf_template,
                            '/etc/apache2/sites-available/{}.conf'.format(domain),
                            context=context, use_jinja=use_jinja)
    ensure_directory('/var/log/apache2/{}'.format(domain))
    modules = [m for m in modules
               if not exists('/etc/apache2/mods-enabled/{}.load'.format(m))]
    if modules:
        run_and_changelog("a2enmod {}".format(' '.join(modules)))
        changed = True
    if not exists('/etc/apache2/sites-enabled/{}.conf'.format(domain)):
        run_and_changelog("a2ensite {}.conf".format(domain))
        changed = True
    if reload_apache and changed:
        run_and_changelog("service apache2 reload")


#
# OpenSSL
#

STARTSSL_INTERMEDIATE_URL = 'https://www.startssl.com/certs/sub.class1.server.ca.pem'

# A test on 2015-04-29 shows that STARTSSL_INTERMEDIATE_URL gives you the same
# certificate as STARTSSL_INTERMEDIATE_SHA2_URL.
STARTSSL_INTERMEDIATE_SHA1_URL = 'https://www.startssl.com/certs/class1/sha1/pem/sub.class1.server.sha1.ca.pem'
STARTSSL_INTERMEDIATE_SHA2_URL = 'https://www.startssl.com/certs/class1/sha2/pem/sub.class1.server.sha2.ca.pem'


def ensure_ssl_key(ssl_key, ssl_csr, ssl_conf, ssl_cert, ssl_intermediate_cert,
                   ssl_intermediate_cert_url, ssl_options):
    """Make sure an SSL certificate exists.

    - ``ssl_key``: filename of the private key (will be generated if missing)
    - ``ssl_csr``: filename of the certificate signing request (will be
      generated if needed)
    - ``ssl_conf``: filename of the ssl configuration file (will be generated
      using ``ssl_options`` if needed and missing)
    - ``ssl_cert``: filename of the SSL certificate (alas this one cannot be
      generated automatically)
    - ``ssl_intermediate_cert``: filename of the SSL intermediate certificate
      (will be downloaded if missing)
    - ``ssl_intermediate_cert_url``: URL for downloading the intermediate
      certificate (e.g. STARTSSL_INTERMEDIATE_URL)
    - ``ssl_options``: a dictionary defining SSL certificate signing request
       generation options, specifically, the arguments to be passed to
       ``generate_ssl_config()`` -- country, state, locality, organization,
       organizational_unit, common_name, and email.

    """
    if not exists(ssl_key, use_sudo=True):
        if not exists(ssl_conf):
            generate_ssl_config(ssl_conf, **ssl_options)
        generate_ssl_key(ssl_key, ssl_csr, ssl_conf)
    if not exists(ssl_csr):
        if not exists(ssl_conf):
            generate_ssl_config(ssl_conf, **ssl_options)
        generate_ssl_csr(ssl_key, ssl_csr, ssl_conf)
    if not exists(ssl_intermediate_cert):
        download_file(ssl_intermediate_cert, ssl_intermediate_cert_url)
    if not exists(ssl_cert):
        changelog_append('# aborting: {ssl_cert} is missing'.format(ssl_cert=ssl_cert))
        with quiet():
            csr = run('cat {ssl_csr}'.format(ssl_csr=ssl_csr))
        abort("{ssl_cert} is missing, please generate it using {ssl_csr}:\n\n{csr}".format(
            ssl_cert=ssl_cert, ssl_csr=ssl_csr, csr=csr))


def generate_ssl_config(conffile, country, state, locality, organization,
                        organizational_unit, common_name, email):
    """Generate a config file for SSL certificates.

    Example::

        generate_ssl_config('/etc/pov/sslreq.conf',
                            country='LT', state='.', locality='Vilnius',
                            organization='POV', organizational_unit='.',
                            common_name='www.example.com',
                            email='root@example.com')

    """
    assert_shell_safe(conffile)
    config = textwrap.dedent("""\
        [ req ]
        default_bits           = 2048
        default_keyfile        = privkey.pem
        distinguished_name     = req_distinguished_name
        prompt                 = no

        [ req_distinguished_name ]
        countryName            = {country}
        stateOrProvinceName    = {state}
        localityName           = {locality}
        organizationName       = {organization}
        organizationalUnitName = {organizational_unit}
        commonName             = {common_name}
        emailAddress           = {email}
    """).format(country=country, state=state, locality=locality,
               organization=organization,
               organizational_unit=organizational_unit,
               common_name=common_name, email=email)
    if upload_file(StringIO(config), conffile):
        changelog_append("# generated {conffile}".format(conffile=conffile))


def generate_ssl_key(keyfile, csrfile, conffile):
    """Generate a new private SSL key and certificate signing request.

    Uses modern defaults for 2015: 2048-bit RSA, SHA-256 signature.
    """
    assert_shell_safe(keyfile, csrfile, conffile)
    changelog_append("# generated {keyfile} and {csrfile}".format(
        keyfile=keyfile, csrfile=csrfile))
    sudo("openssl req -config {conffile} -newkey rsa:2048 -nodes"
         " -keyout {keyfile} -sha256 -out {csrfile}".format(
             keyfile=keyfile, csrfile=csrfile, conffile=conffile))


def generate_ssl_csr(keyfile, csrfile, conffile):
    """Generate a new certificate signing request for a given SSL private key.

    Uses modern defaults for 2015: SHA-256 signature.
    """
    assert_shell_safe(keyfile, csrfile, conffile)
    changelog_append("# generated {csrfile}".format(csrfile=csrfile))
    sudo("openssl req -config {conffile} -new -key {keyfile} -sha256"
         " -out {csrfile}".format(
             keyfile=keyfile, csrfile=csrfile, conffile=conffile))


#
# Postfix
#

def install_postfix_virtual_table(local, remote, changelog_append=True):
    """Upload a Postfix virtual table and install it.

    Takes care of
    - uploading the local file to remote
    - file permissions and ownership (0644, root:root)
    - running postmap
    - adding the table to /etc/postfix/main.cf virtual_maps
    - making sure that postfix accepts outside connections
      (inet_interfaces != loopback-only)
    - changelog updates for all of the above

    If ``changelog_append`` is False creates a new timestamped header.
    If it's True, appends to the current message.
    """
    assert_shell_safe(remote)
    if upload_file(local, remote):
        changelog('# updated {remote}'.format(remote=remote),
                  append=changelog_append)
        run_and_changelog("postmap {remote}".format(remote=remote))
    # consider running postmap if the file exists and hasn't changed but the
    # corresponding .map file is missing or outdated
    add_postfix_virtual_map('hash:' + remote)
    make_postfix_public()


def get_postfix_setting(setting):
    """Get the current value of a postfix setting"""
    assert_shell_safe(setting)
    with quiet():
        current_setting = run("postconf -h {setting}".format(setting=setting))
    if current_setting.startswith('postconf: warning:'):
        # assume "postconf: warning: {setting}: unknown parameter"
        current_setting = ''
    return current_setting


def parse_postfix_setting(current_setting):
    """Parse a comma-separated postfix setting.

    Returns a list of (non-empty) strings.
    """
    return filter(None, map(str.strip, current_setting.split(',')))


def add_postfix_virtual_map(entry):
    """Add an entry to postfix's virtual_maps.

    Takes care to
    - preserve preexisting virtual maps
    - reload postfix's configurationa after changing it
    - document all the changes in the changelog

    Idempotent: does nothing if entry is already included in virtual_maps.
    """
    assert_shell_safe(entry, extra_allow=':')
    current_setting = get_postfix_setting('virtual_alias_maps')
    if current_setting != '$virtual_maps':
        # TBH maybe we should ignore the legacy $virtual_maps and instead
        # just use $virtual_alias_maps?
        abort("Unexpected virtual_alias_maps setting ({})".format(current_setting))
    add_postfix_setting('virtual_maps', entry)


def add_postfix_setting(setting, entry, reload_postfix=True):
    """Add an entry to a comma-separated postfix setting.

    Takes care to
    - preserve preexisting values
    - reload postfix's configuration after changing it
    - document all the changes in the changelog

    Idempotent: does nothing if entry is already included in the setting.

    Returns True if the setting was modified, False if it was untouched.
    """
    assert_shell_safe(setting)
    assert_shell_safe(entry, extra_allow=':')
    old_value = get_postfix_setting(setting)
    items = parse_postfix_setting(old_value)
    if entry in items:
        return False
    else:
        items.append(entry)
        new_value = ', '.join(items)
        if "'" in new_value:
            abort("Cannot handle apostrophes in {setting} setting ({old_value}),"
                  " not touching anything!".format(setting=setting,
                                                   old_value=old_value))
        changelog_append('# adding {entry} to {setting} in /etc/postfix/main.cf'.format(
            entry=entry, setting=setting))
        res = run_and_changelog("postconf {setting}='{new_value}'".format(
            setting=setting, new_value=new_value))
        if res.startswith("postconf: warning:"):
            # Uhh on Ubuntu 10.04 postconf can't handle non-standard variables at all
            changelog_append("  | %s" % res.rstrip())
            abort("Your version of postconf ignores unknown settings; you'll have to edit /etc/postfix/main.cf and reload postfix manually.")
        if reload_postfix:
            run_and_changelog("postfix reload")
        return True


def make_postfix_public():
    """Make sure postfix accepts connections from outside.

    Takes care to
    - restart postfix if necessary
    - document all the changes in the changelog
    """
    with quiet():
        current_setting = run("postconf -h inet_interfaces")
    if current_setting == 'loopback-only':
        run_and_changelog("postconf inet_interfaces=all")
        run_and_changelog("service postfix restart")


#
# pov-admin-tools
#

def has_new_changelog_message():
    """Check if new-changelog-entry is installed.

    (You can get it by installing pov-admin-tools.)
    """
    return (exists('/usr/sbin/new-changelog-entry') or
            exists('/usr/local/sbin/new-changelog-entry'))


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
    # NB: no assert_shell_safe(): quote() ought to take care of everything.
    if not optional or has_new_changelog_message():
        cmd = 'new-changelog-entry'
        if append:
            cmd += ' -a'
        if context is not None:
            message = message.format(**context)
        cmd += ' ' + quote(message)
        run_as_root(cmd)


def changelog_append(message, context=None, optional=True):
    """Append a message to /root/Changelog.

    Shortcut for changelog(message, append=True).
    """
    changelog(message, context, append=True, optional=optional)


def changelog_banner(message, context=None, optional=True):
    """Append a banner message to /root/Changelog."""
    changelog("#\n  # %s\n  #" % message, context, optional=optional)


def run_and_changelog(command, append=True):
    """Run a command and also append it to /root/Changelog"""
    changelog(command, append=append)
    return run_as_root(command)


def run_as_root(command):
    """Run a command as root; use sudo only if necessary."""
    current_user = env.host_string.rpartition('@')[0] or env.user
    if current_user != 'root':
        return sudo(command, user='root')
    else:
        return run(command)


#
# Instance management
#


class Instance(dict):
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
        # This trick lets us access dict keys as if they were object attributes
        # and vice versa.
        self.__dict__ = self
        self.name = name
        self.host = host
        self.__dict__.update(kwargs)

    def _asdict(self):
        """(DEPRECATED) Return the instance parameters as a dict.

        Useful for string formatting, e.g. ::

            print('{name} is on {host}'.format(**instance._asdict()))

        but since now you can do ::

            print('{name} is on {host}'.format(**instance))

        this method is pointless and is retained for backwards compatibility
        only.

        Mimics the API of ``collections.namedtuple``.
        """
        return self

    REQUIRED = object()

    @classmethod
    def with_params(cls, **params):
        """Define an instance subclass

        Usage example::

            from pov_fabric import Instance as BaseInstance

            Instance = BaseInstance.with_params(
                required_arg1=BaseInstance.REQUIRED,
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

    @classmethod
    def define_alias(cls, alias, name):
        """Define an alias for an instance.

        Defines an instance selector task named ``alias`` that selects an
        instance named ``name``.

        Usage example::

            Instance.define_alias('prod', 'srv1.example.com')

        """
        _define_instance_task(alias, name, stacklevel=2)


def _define_instance(instance):
    """Define an instance.

    Instances are stored in the ``env.instances`` dictionary, which is created
    on demand.
    """
    if not _valid_task_name(instance.name):
        abort("'{name}' is not a valid instance name.".format(name=instance.name))
    if not hasattr(env, 'instances'):
        env.instances = {}
    if instance.name in env.instances:
        abort("Instance {name} is already defined.".format(name=instance.name))
    env.instances[instance.name] = instance


def _define_instance_task(name, instance_name=None, stacklevel=1):
    """Define an instance task

    This task will set env.instance to the name of the task.
    """
    if not _valid_task_name(name):
        abort("'{name}' is not a valid task name.".format(name=name))
    if instance_name is None:
        instance_name = name
    def fn():
        env.instance = instance_name
    fn.__doc__ = """Select instance '%s' for subsequent tasks.""" % instance_name
    instance_task = task(name=name)(fn)
    fn_name = _pythonify_name(name)
    module_globals = sys._getframe(stacklevel).f_globals
    while fn_name in module_globals:
        fn_name += '_'
    module_globals[fn_name] = instance_task


def _valid_task_name(name):
    """Check if ``name`` is a valid Fabric task name"""
    if not name:
        return False
    if name.startswith('-'):
        return False
    if ' ' in name:
        return False
    if ':' in name:
        return False
    if '.' in name:
        return False
    return True


def _pythonify_name(name):
    """Coerce the name to a valid Python identifier"""
    name = ''.join(c if c.isalnum() else '_' for c in name)
    if name[:1].isdigit():
        name = '_' + name
    return name


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

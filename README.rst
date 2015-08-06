Fabric Helpers
==============

This is a collection of helpers we use in Fabric_ scripts.  They're primarily
intended to manage Ubuntu servers (12.04 LTS or 14.04 LTS).

.. _Fabric: http://www.fabfile.org/

.. contents::


Helpers (aka why would I want this?)
------------------------------------

APT packages:

- ``ensure_apt_not_outdated()`` - runs ``apt-get update`` at most once a day
- ``install_packages("vim screen build-essential")``
- ``install_missing_packages("vim screen build-essential")``
- ``if not package_installed('git'): ...``
- ``if not package_available('pov-admin-helpers'): ...``

User accounts:

- ``ensure_user("myusername")``

SSH:

- ``ensure_known_host("example.com ssh-rsa AAA....")``

Locales:

- ``ensure_locales("en", "lt")``

Files and directories:

- ``ensure_directory("/srv/data", mode=0o700)``
- ``upload_file('crontab', '/etc/cron.d/mycrontab')``
- ``generate_file('crontab.in', '/etc/cron.d/mycrontab', context, use_jinja=True)``
- ``download_file('/home/user/.ssh/authorized_keys', 'https://example.com/ssh.pubkey')``

GIT:

- ``git_clone("git@github.com:ProgrammersOfVilnius/project.git", "/opt/project")``
- ``git_update("/opt/project")``

PostgreSQL:

- ``ensure_postgresql_user("username")``
- ``ensure_postgresql_db("dbname", "owner")``

Apache:

- ``ensure_ssl_key(...)``
- ``install_apache_website('apache.conf.in', 'example.com', context, use_jinja=True, modules='ssl rewrite proxy_http')```

Postfix:

- ``install_postfix_virtual_table('virtual', '/etc/postfix/virtual.example.com')```
- ``make_postfix_public()``

Keeping a changelog in /root/Changelog (requires
/usr/sbin/new-changelog-entry from pov-admin-tools_)

- ``changelog("# Installing stuff")``
- ``changelog_append("# more stuff")``
- ``changelog_banner("Installing stuff")``
- ``run_and_changelog("apt-get install stuff")``

plus many other helpers have ``changelog`` and/or ``changelog_append``
arguments to invoke these implicitly.

.. _pov-admin-tools: https://github.com/ProgrammersOfVilnius/pov-admin-tools


Instance management API
-----------------------

All of my fabfiles can manage several *instances* of a particular service.
Externally this looks like ::

  fab instance1 task1 task2 instance2 task3

which executes Fabric tasks ``task1`` and ``task2`` on instance ``instance1``
and then executes ``task3`` on ``instance2``.

An instance defines various parameters, such as

- what server hosts it
- where on the filesystem it lives
- what Unix user IDs are used
- what database is used for this instance
- etc.

To facilitate this ``pov_fabric`` provides three things:

1. An ``Instance`` class that should be subclassed to provide your own instances

   .. code:: python

    from pov_fabric import Instance as BaseInstance

    class Instance(BaseInstance):
        def __init__(self, name, host, home='/opt/sentry', user='sentry',
                     dbname='sentry'):
            super(Instance, self).Instance.__init__(name, host)
            self.home = home
            self.user = user
            self.dbname = dbname

   and since that's a bit repetitive there's a helper

   .. code:: python

    from pov_fabric import Instance as BaseInstance

    Instance = BaseInstance.with_params(
        home='/opt/sentry',
        user='sentry',
        dbname='sentry',
    )

   which is equivalent to the original manual subclassing.

   (BTW you can also add parameters with no sensible default this way, e.g.
   ``BaseInstance.with_params(user=BaseInstance.REQUIRED)``.)

2. An ``Instance.define()`` class method that defines new instances and
   creates tasks for selecting them

   .. code:: python

    Instance.define(
        name='testing',
        host='root@vagrantbox',
    )
    Instance.define(
        name='production',
        host='server1.pov.lt',
    )
    Instance.define(
        name='staging',
        host='server1.pov.lt',
        home='/opt/sentry-staging',
        user='sentry-staging',
        dbname='sentry-staging',
    )

   (BTW you can also define aliases with ``Instance.define_alias('prod',
   'production')``.)

3. A ``get_instance()`` function that returns the currently selected instance
   (or aborts with an error if the user didn't select one)

   .. code:: python

    from pov_fabric import get_instance

    @task
    def look_around():
        instance = get_instance()
        with settings(host_string=instance.host):
            run('hostname')


Previously I used a slightly different command style ::

    fab task1:instance1 task2:instance1 task3:instance2

and this can still be supported if you write your tasks like this

.. code:: python

    @task
    def look_around(instance=None):
        instance = get_instance(instance)
        with settings(host_string=instance.host):
            run('hostname')

Be careful if you mix styles, e.g. ::

    fab instance1 task1 task2:instance2 task3

will run ``task1`` and ``task3`` on ``instance1`` and it will run ``task2`` on
``instance2``.


Usage
-----

Get the latest release from PyPI::

    pip install pov-fabric-helpers

and then import the helpers you want in your ``fabfile.py``

.. code:: python

    from fabric.api import ...
    from pov_fabric import ...


Usage as a git submodule
~~~~~~~~~~~~~~~~~~~~~~~~

You can add this repository as a git submodule

.. code:: bash

  cd ~/src/project
  git submodule add https://github.com/ProgrammersOfVilnius/pov-fabric-helpers

and in your ``fabfile.py`` add

.. code:: python

  sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'pov-fabric-helpers'))
  if not os.path.exists(os.path.join(sys.path[0], 'pov_fabric.py')):
      sys.exit("Please run 'git submodule update --init'.")
  from pov_fabric import ...


Testing Fabfiles with Vagrant
-----------------------------

I don't know about you, but I was never able to write a fabfile.py that worked
on the first try.  Vagrant_ was very useful for testing fabfiles without
destroying real servers in the process.  Here's how:

- Create a ``Vagrantfile`` somewhere with

  .. code:: ruby

    Vagrant.configure("2") do |config|
      config.vm.box = "ubuntu/precise64"  # Ubuntu 12.04
      config.vm.provider :virtualbox do |vb|
        vb.customize ["modifyvm", :id, "--memory", "1024"]
      end
    end

- Run ``vagrant up``

- Run ``vagrant ssh-config`` and copy the snippet to your ``~/.ssh/config``,
  but change the name to ``vagrantbox``, e.g. ::

    Host vagrantbox
      HostName 127.0.0.1
      User vagrant
      Port 2222
      UserKnownHostsFile /dev/null
      StrictHostKeyChecking no
      PasswordAuthentication no
      IdentityFile ~/.vagrant.d/insecure_private_key
      IdentitiesOnly yes
      LogLevel FATAL

- Test that ``ssh vagrantbox`` works

- In your ``fabfile.py`` create a testing instance

  .. code:: python

    Instance.define(
        name='testing',
        host='vagrant@vagrantbox',
        ...
    )

- Test with ``fab testing install`` etc.

.. _Vagrant: https://www.vagrantup.com/

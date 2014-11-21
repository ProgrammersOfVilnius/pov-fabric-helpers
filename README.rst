Fabric Helpers
==============

This is a collection of helpers we use in Fabric_ scripts.  They're primarily
intended to manage Ubuntu servers (10.04 LTS, 12.04 LTS or 14.04 LTS).

.. _Fabric: http://www.fabfile.org/

A possibly-incomplete list of them:

- ``ensure_apt_not_outdated()``
- ``install_packages("vim screen build-essential")``
- ``ensure_known_host("hostname ssh-rsa AAA....")``
- ``ensure_user("username")``
- ``git_clone("git@github.com:ProgrammersOfVilnius/project.git", "/opt/project")``
- ``git_update("/opt/project")``
- ``ensure_postgresql_user("username")``
- ``ensure_postgresql_db("dbname", "owner")``
- ``changelog("# Installing stuff")`` (requires pov-admin-tools_)
- ``changelog_append("# more stuff")`` (requires pov-admin-tools_)

.. _pov-admin-tools: https://github.com/ProgrammersOfVilnius/pov-admin-tools

.. contents::


Usage
-----

For now add this repository as a git submodule

.. code:: bash

  cd ~/src/project
  git submodule add https://github.com/ProgrammersOfVilnius/pov-fabric-helpers

and in your ``fabfile.py`` add

.. code:: python

  sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'pov-fabric-helpers'))
  if not os.path.exists(os.path.join(sys.path[0], 'pov_fabric.py')):
      sys.exit("Please run 'git submodule update --init'.")
  from pov_fabric import ...


Instance management
-------------------

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

2. ``Instance.define()`` that defines new instances and creates tasks for
   selecting them

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

3. A ``get_instance()`` method that returns the currently selected instance
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


Testing Fabfiles with Vagrant
-----------------------------

I don't know about you, but I was never able to write a fabfile.py that worked
on the first try.  Vagrant_ was very useful for testing fabfiles without
destroying real servers in the process.  Here's how:

- Create a ``Vagrantfile`` somewhere with

  .. code:: ruby

    Vagrant.configure("2") do |config|
      config.vm.box = "precise64"  # Ubuntu 12.04
      config.vm.box_url = "http://files.vagrantup.com/precise64.box"
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
      IdentityFile /home/mg/.vagrant.d/insecure_private_key
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

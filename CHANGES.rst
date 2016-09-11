Changelog
=========


0.3 (2016-09-11)
----------------

- ``register_host_key()`` now takes ``fingerprints`` so you can specify both
  MD5 and SHA256 fingerprints.

  Use either ``register_host_key(key, fingerprint=md5_fprint)`` or
  ``register_host_key(key, fingerprints=[md5_fprint, sha256_fprint])``.

- Low-level helper ``ssh_key_fingerprint()`` now takes ``force_md5`` so you
  can insist on MD5 instead of whatever OpenSSH gives you by default (which is
  SHA256 for modern OpenSSH).


0.2 (2015-08-06)
----------------

- New helpers:

  - ``git_update()``, ``register_host_key()``,
  - ``ensure_locales()``,
  - ``changelog_banner()``, ``run_and_changelog()``,
    ``has_new_changelog_message()``,
  - ``install_missing_packages()``, ``package_available()``,
  - ``upload_file()``, ``generate_file()``, ``ensure_directory()``,
    ``download_file()``,
  - ``install_postfix_virtual_table()``,
  - ``install_apache_website()``,
  - ``ensure_ssl_key()``.

- New optional arguments for existing helpers:

  - ``git_clone()`` now takes ``branch`` and ``changelog``.
  - ``ensure_user()`` now takes ``shell``, ``home``, ``create_home``, and
    ``changelog``.
  - ``install_packages()`` now takes ``changelog``.
  - ``changelog()`` now takes ``context``.
  - ``changelog_append()`` now takes ``context`` and ``optional``.
  - ``changelog_banner()`` now takes ``context`` and ``optional``.

- Increased safety:

  - all helpers check their arguments for unsafe shell metacharacters.
  - changelog() and friends quote the arguments correctly.

- Improved instance API:

  - allow ``str.format(**instance)`` (by making Instance a subclass of
    ``dict``).
  - allow instance aliases defined via ``Instance.define_alias(alias, name)``
    static method.

- Bugfixes:

  - ``ensure_postgresql_db()`` now works correctly on Ubuntu 14.04.
  - ``run_as_root`` now correctly handles ``env.host_string`` with no
    username part.

- New low-level helpers you're probably not interested in, unless you're
  writing your own helpers:

  - ``aslist()``, ``assert_shell_safe()``,
  - ``ssh_key_fingerprint()``,
  - ``render_jinja2()``, ``render_sinterp()``,
  - ``parse_git_repo()``,
  - ``generate_ssl_config()``, ``generate_ssl_key()``, ``generate_ssl_csr()``,
  - ``get_postfix_setting()``, ``parse_postfix_setting()``,
    ``add_postfix_virtual_map()``, ``add_postfix_setting()``,
  - ``run_as_root()``.


0.1 (2014-11-19)
----------------

- First public release.

- Helpers:

  - ``ensure_apt_not_outdated()``, ``package_installed()``,
    ``install_packages()``,
  - ``ensure_known_host()``, ``ensure_user()``,
  - ``git_clone()``,
  - ``ensure_postgresql_user()``, ``ensure_postgresql_db()``,
  - ``changelog()``, ``changelog_append()``.

- Instance API:

  - ``class Instance``, ``Instance.with_params()``,
    ``Instance.REQUIRED``, ``Instance.define()``.
  - ``instance._asdict()``.
  - ``get_instance()``.

- Low-level helpers you're probably not interested in, unless you're
  writing your own helpers:

  - ``asbool()``,
  - ``postgresql_user_exists()``, ``postgresql_db_exists()``.

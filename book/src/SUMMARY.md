# Kanidm

- [Introduction to Kanidm](introduction_to_kanidm.md)

- [Evaluation Quickstart](evaluation_quickstart.md)

- [Supported Features](supported_features.md)
- [Project Support](support.md)

- [Installing the Server](installing_the_server.md)
  - [Choosing a Domain Name](choosing_a_domain_name.md)
  - [Preparing for your Deployment](preparing_for_your_deployment.md)
  - [Server Configuration](server_configuration.md)
  - [Security Hardening](security_hardening.md)
  - [Server Updates](server_updates.md)

- [Client Tools](client_tools.md)
  - [Installing Client Tools](installing_client_tools.md)

- [Administration](administration.md)
  - [Backup and Restore](backup_and_restore.md)
  - [Database Maintenance](database_maintenance.md)
  - [Domain Rename](domain_rename.md)
  - [Monitoring the platform](monitoring_the_platform.md)
  - [Recycle Bin](recycle_bin.md)

- [Accounts and Groups](accounts/intro.md)
  - [People Accounts](accounts/people_accounts.md)
  - [Authentication and Credentials](accounts/authentication_and_credentials.md)
  - [Groups](accounts/groups.md)
  - [Service Accounts](accounts/service_accounts.md)
  - [Anonymous Account](accounts/anonymous_account.md)
  - [Account Policy](accounts/account_policy.md)
  - [POSIX Accounts and Groups](accounts/posix_accounts_and_groups.md)

- [Service Integrations](integrations/readme.md)
  - [PAM and nsswitch](integrations/pam_and_nsswitch.md)
    - [SUSE / OpenSUSE](integrations/pam_and_nsswitch/suse.md)
    - [Fedora](integrations/pam_and_nsswitch/fedora.md)
    - [Troubleshooting](integrations/pam_and_nsswitch/troubleshooting.md)
  - [SSSD](integrations/sssd.md)
  - [SSH Key Distribution](integrations/ssh_key_distribution.md)
  - [Oauth2](integrations/oauth2.md)
  - [LDAP](integrations/ldap.md)
  - [RADIUS](integrations/radius.md)

- [Service Integration Examples](examples/readme.md)
  - [Kubernetes Ingress](examples/kubernetes_ingress.md)
  - [Traefik](examples/traefik.md)

- [Replication](repl/readme.md)
  - [Planning](repl/planning.md)
  - [Deployment](repl/deployment.md)
  - [Administration](repl/administration.md)

- [Synchronisation](sync/concepts.md)
  - [FreeIPA](sync/freeipa.md)
  - [LDAP](sync/ldap.md)

- [Access Control](access_control/intro.md)

# Support

- [Troubleshooting](troubleshooting.md)
- [Frequently Asked Questions](frequently_asked_questions.md)
- [Glossary](glossary.md)

# For Developers

- [Developer Guide](developers/readme.md)
- [Developer Ethics](developers/developer_ethics.md)
- [Frequently Asked Questions](developers/faq.md)
- [Design Documents]()
  - [Access Profiles 2022](developers/designs/access_profiles_rework_2022.md)
  - [Access Profiles Original](developers/designs/access_profiles_original.md)
  - [Access Control Defaults](developers/designs/access_control_defaults.md)
  - [Architecture](developers/designs/architecture.md)
  - [Authentication flow](developers/designs/authentication_flow.md)
  - [Cryptography Key Domains (2024)](developers/designs/cryptography_key_domains.md)
  - [Domain Join - Machine Accounts](developers/designs/domain_join_machine_accounts.md)
  - [Elevated Priv Mode](developers/designs/elevated_priv_mode.md)
  - [Oauth2 Refresh Tokens](developers/designs/oauth2_refresh_tokens.md)
  - [Replication Coordinator](developers/designs/replication_coordinator.md)
  - [Replication Design and Notes](developers/designs/replication_design_and_notes.md)
  - [REST Interface](developers/designs/rest_interface.md)
- [Python Module](developers/python_module.md)
- [RADIUS Module Development](developers/radius.md)
- [Release Checklist](developers/release_checklist.md)
- [Packaging](developers/packaging.md)
  - [Debian/Ubuntu](developers/debian_ubuntu_packaging.md)

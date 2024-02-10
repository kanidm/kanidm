# Kanidm

- [Introduction to Kanidm](intro.md)
- [Supported Features](features.md)

- [Evaluation Quickstart](quickstart.md)

- [Installing the Server](installing_the_server.md)
  - [Choosing a Domain Name](choosing_a_domain_name.md)
  - [Preparing for your Deployment](prepare_the_server.md)
  - [Server Configuration and Install](server_configuration.md)
  - [Platform Security Hardening](security_hardening.md)
  - [Server Updates](server_update.md)

- [Client Tools](client_tools.md)
  - [Installing client tools](installing_client_tools.md)

- [Administration](administrivia.md)
  - [Backup and Restore](backup_restore.md)
  - [Database Maintenance](database_maint.md)
  - [Domain Rename](domain_rename.md)
  - [Monitoring the platform](monitoring.md)
  - [The Recycle Bin](recycle_bin.md)

- [Accounts and Groups](accounts/intro.md)
  - [People Accounts](accounts/people.md)
  - [Authentication and Credentials](accounts/authentication.md)
  - [Groups](accounts/groups.md)
  - [Service Accounts](accounts/service.md)
  - [Anonymous](accounts/anonymous.md)
  - [Account Policy](accounts/policy.md)
  - [POSIX Accounts and Groups](accounts/posix.md)

- [Service Integrations](integrations/readme.md)
  - [PAM and nsswitch](integrations/pam_and_nsswitch.md)
    - [SUSE / OpenSUSE](integrations/pam_and_nsswitch/suse.md)
    - [Fedora](integrations/pam_and_nsswitch/fedora.md)
    - [Troubleshooting](integrations/pam_and_nsswitch/troubleshooting.md)
  - [SSSD](integrations/sssd.md)
  - [SSH Key Distribution](integrations/ssh_key_dist.md)
  - [Oauth2](integrations/oauth2.md)
  - [LDAP](integrations/ldap.md)
  - [RADIUS](integrations/radius.md)

- [Service Integration Examples](examples/readme.md)
  - [Kubernetes Ingress](examples/k8s_ingress_example.md)
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
- [Glossary of Technical Terms](glossary.md)

# For Developers

- [Developer Guide](DEVELOPER_README.md)
- [Frequently Asked Questions](developers/faq.md)
- [Design Documents]()
  - [Access Profiles 2022](developers/designs/access_profiles_rework_2022.md)
  - [Access Profiles Original](developers/designs/access_profiles_and_security.md)
  - [Access Control Defaults](developers/designs/access_control_defaults.md)
  - [Architecture](developers/designs/architecture.md)
  - [Authentication flow](developers/designs/authentication_flow.md)
  - [Domain Join](developers/designs/domain_join.md)
  - [Elevated Priv Mode](developers/designs/elevated_priv_mode.md)
  - [Oauth2 Refresh Tokens](developers/designs/oauth2_refresh_tokens.md)
  - [Replication Coordinator](developers/designs/replication_coord.md)
  - [Replication Internals](developers/designs/replication.md)
  - [REST Interface](developers/designs/rest_interface.md)
- [Python Module](developers/python.md)
- [RADIUS Integration](developers/radius.md)
- [Packaging](packaging.md)
  - [Debian/Ubuntu](packaging_debs.md)

# FreeBSD

## Nsswitch

Unlike Linux, FreeBSD requires you to change `compat` to `files` in `/etc/nsswitch.conf`.

```text
group: kanidm files
passwd: kanidm files
```

## PAM

Backup your PAM files:

```bash
cp -a /etc/pam.d /root/pam.d.backup
```

```text
# /etc/pam.d/common
# auth
auth            required        /usr/local/lib/libpam_kanidm.so try_first_pass

# account
account         required        pam_login_access.so
account         required        /usr/local/lib/libpam_kanidm.so

# session
session         required        /usr/local/lib/libpam_kanidm.so

# password
password        required        pam_unix.so             no_warn try_first_pass
# Password changes via pam_kanidm.so are not yet supported.
# password        required        /usr/local/lib/libpam_kanidm.so             no_warn try_first_pass
```

```text
# /etc/pam.d/system

# auth
auth            include         common

# account
account         include         common

# session
session         required        pam_lastlog.so          no_fail
session         required        pam_xdg.so
session         include         common

# password
password          include         common
```

```text
# /etc/pam.d/sshd

# auth
auth            include         common

# account
account         required        pam_nologin.so
account         include         common

# session
session         include         common

# password
password          include         common
```

### Optional

```text
# /etc/pam.d/atrun

# Note well: enabling pam_nologin for atrun will currently result
# in jobs discarded, not just delayed, during a no-login period.

# account         required        pam_nologin.so
account         include         common
```

```text
# /etc/pam.d/cron

account         required        pam_nologin.so
account         include         common
```

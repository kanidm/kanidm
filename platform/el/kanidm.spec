Name:           kanidm
Version:        %{_version}
Release:        %{_release}
Summary:        A simple, secure and fast identity management platform
License:        MPL-2.0
URL:            https://github.com/Firstyear/kanidm

Requires:       %{name}-client
Requires:       %{name}-unixd
SOURCE1:        kanidm.sysusers
%{?systemd_requires}

%description
Kanidm is a simple and secure identity management platform, which provides
services to allow other systems and application to authenticate against. The
project aims for the highest levels of reliability, security and ease of use.


%package client
Summary:        Client tools for interacting with Kanidm
License:        MPL-2.0

%description client
Client utilities for interactive with kanidm servers


%package server
Summary:        Kanidm server
License:        MPL-2.0
Requires:       %{name}-client

%description server
Kanidm server


%package unixd
Summary:        Kanidm authentication for use on clients
License:        MPL-2.0
Requires:       %{name}-client


%description unixd
This package provides PAM and NSS modules for resolving POSIX entries from Kanidm.


%package docs
Summary:        Kanidm book and rustdoc
License:        MPL-2.0

%description docs
Documentation for using and configuring Kanidm.


#----------------------------------------------------------------------------

%prep

%build

%install
# Completions
install -D -d -m 0755 %{buildroot}%{_datadir}/zsh/site-functions/
install -D -d -m 0755 %{buildroot}%{_datadir}/bash-completion/completions/
cp %{_builddir}/target/release/build/completions/_kan*                          %{buildroot}%{_datadir}/zsh/site-functions/
cp %{_builddir}/target/release/build/completions/kan*.bash                      %{buildroot}%{_datadir}/bash-completion/completions

# Binaries
install -D -d -m 0755 %{buildroot}%{_bindir}
install -m 0755 %{_builddir}/target/release/kanidm                              -t %{buildroot}/%{_bindir}/

install -D -d -m 0755 %{buildroot}%{_sbindir}
install -m 0755 %{_builddir}/target/release/kanidmd                             -t %{buildroot}/%{_sbindir}
install -m 0755 %{_builddir}/target/release/kanidm-unix                         -t %{buildroot}/%{_sbindir}
install -m 0755 %{_builddir}/target/release/kanidm_ssh_authorizedkeys           -t %{buildroot}/%{_sbindir}
install -m 0755 %{_builddir}/target/release/kanidm_ssh_authorizedkeys_direct    -t %{buildroot}/%{_sbindir}
install -m 0755 %{_builddir}/target/release/kanidm_unixd                        -t %{buildroot}/%{_sbindir}
install -m 0755 %{_builddir}/target/release/kanidm_unixd_tasks                  -t %{buildroot}/%{_sbindir}

install -D -d -m 0755 %{buildroot}%{_libdir} %{buildroot}/%{_lib}/security
install -m 0644 %{_builddir}/target/release/libnss_kanidm.so                    %{buildroot}/%{_libdir}/libnss_kanidm.so.2
install -m 0644 %{_builddir}/target/release/libpam_kanidm.so                    %{buildroot}/%_lib/security/pam_kanidm.so

# Services
install -D -d -m 0755 %{buildroot}%{_unitdir}
install -m 0644 %{_builddir}/platform/systemd/kanidmd.service                   -t %{buildroot}%{_unitdir}
install -m 0644 %{_builddir}/platform/systemd/kanidm-unixd.service              -t %{buildroot}%{_unitdir}
install -m 0644 %{_builddir}/platform/systemd/kanidm-unixd-tasks.service        -t %{buildroot}%{_unitdir}
install -pDm 0644 %{SOURCE1}                                                     %{buildroot}%{_sysusersdir}/kanidm-server.conf

# Configuration
install -D -d -m 0755 %{buildroot}%{_sysconfdir}/kanidm/
install -m 0640 %{_builddir}/examples/server.toml                               -t %{buildroot}%{_sysconfdir}/kanidm
install -m 0644 %{_builddir}/examples/config                                    -t %{buildroot}%{_sysconfdir}/kanidm
install -m 0644 %{_builddir}/examples/unixd                                     -t %{buildroot}%{_sysconfdir}/kanidm

# Data & state
install -D -d -m 0755 %{buildroot}%{_datadir}/kanidm/docs/
install -D -d -m 0755 %{buildroot}%{_datadir}/kanidm/ui/pkg
install -D -d -m 0750 %{buildroot}%{_sharedstatedir}/kanidm
cp -r %{_builddir}/docs                                                          %{buildroot}%{_datadir}/kanidm/docs/
cp -r %{_builddir}/server/web_ui/pkg/                                            %{buildroot}%{_datadir}/kanidm/ui/
find %{buildroot}%{_datadir}/kanidm/ -type d -exec chmod 0755 {} +
find %{buildroot}%{_datadir}/kanidm/ -type f -exec chmod 0644 {} +



#----------------------------------------------------------------------------

%pre server
%sysusers_create_compat %{SOURCE1}

%post server
%systemd_post kanidmd.service

%preun server
%systemd_preun kanidmd.service

%postun server
%systemd_postun kanidmd.service

#----------------------------------------------------------------------------

%post unixd
%systemd_post kanidm-unixd.service
%systemd_post kanidm-unixd-tasks.service

%preun unixd
%systemd_preun kanidm-unixd.service
%systemd_preun kanidm-unixd-tasks.service

%postun unixd
%systemd_postun kanidm-unixd.service
%systemd_postun kanidm-unixd-tasks.service

#----------------------------------------------------------------------------

%files
%defattr(-,root,root)


%files server
%{_sbindir}/kanidmd
%{_unitdir}/kanidmd.service
%{_sysusersdir}/kanidm-server.conf

%dir %{_datadir}/kanidm
%{_datadir}/kanidm/**/*
%{_datadir}/zsh/site-functions/_kanidmd
%{_datadir}/bash-completion/completions/kanidmd.bash

%attr(0750, kanidm, kanidm) %dir %{_sharedstatedir}/kanidm
%attr(0755, root, kanidm) %dir %{_sysconfdir}/kanidm
%attr(0640, root, kanidm) %config(noreplace) %{_sysconfdir}/kanidm/server.toml


%files client
%defattr(-,root,root)
%{_bindir}/kanidm
%attr(0644, root, root) %config(noreplace) %{_sysconfdir}/kanidm/config
%{_datadir}/zsh/site-functions/_kanidm
%{_datadir}/bash-completion/completions/kanidm.bash


%files unixd
%{_libdir}/libnss_kanidm.so.2
%attr(0644, root, root) %config(noreplace) %{_sysconfdir}/kanidm/unixd
/%_lib/security/pam_kanidm.so
%{_sbindir}/kanidm-unix
%{_sbindir}/kanidm_ssh_authorizedkeys
%{_sbindir}/kanidm_ssh_authorizedkeys_direct
%{_sbindir}/kanidm_unixd
%{_sbindir}/kanidm_unixd_tasks
%{_unitdir}/kanidm-unixd.service
%{_unitdir}/kanidm-unixd-tasks.service
%{_datadir}/zsh/site-functions/_kanidm_*
%{_datadir}/bash-completion/completions/kanidm_*.bash


%files docs
%dir %{_datadir}/kanidm
%dir %{_datadir}/kanidm/docs
%doc %{_datadir}/kanidm/docs/*

%changelog
* Fri Apr 28 2023 Georgi Valkov <georgi.t.valkov@gmail.com>
- Initial package

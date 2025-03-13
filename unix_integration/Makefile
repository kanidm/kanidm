


dev_install:
	@ echo "WARNING: THIS WILL BREAK EXISTING UNIXD INSTALLS"
	@ echo "ctrl-c now if this is not what you want"
	@ read
	@ echo "LAST CHANCE"
	@ sleep 5
	ln -s -f $(pwd)/../platform/opensuse/kanidm-unixd.service /etc/systemd/system/kanidm-unixd.service
	ln -s -f $(pwd)/../platform/opensuse/kanidm-unixd-tasks.service /etc/systemd/system/kanidm-unixd-tasks.service
	ln -s -f $(pwd)/../target/debug/kanidm-unix /usr/sbin/kanidm-unix
	ln -s -f $(pwd)/../target/debug/kanidm_ssh_authorizedkeys /usr/sbin/kanidm_ssh_authorizedkeys
	ln -s -f $(pwd)/../target/debug/kanidm_unixd_tasks /usr/sbin/kanidm_unixd_tasks
	ln -s -f $(pwd)/../target/debug/kanidm_unixd /usr/sbin/kanidm_unixd
	ln -s -f $(pwd)/../target/debug/libpam_kanidm.so /lib64/security/pam_kanidm.so
	ln -s -f $(pwd)/../target/debug/libnss_kanidm.so /usr/lib64/libnss_kanidm.so.2



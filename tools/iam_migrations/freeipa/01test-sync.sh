
 ldapsearch -H ldap://localhost -D 'cn=Directory Manager' -w $(cat ipa.pw) -b 'cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au' -x -E \!sync=ro





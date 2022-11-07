use ldap3_client::LdapSyncRepl;

#[tokio::test]
async fn test_ldap_to_scim() {
    let _sync_request: LdapSyncRepl =
        serde_json::from_str(TEST_LDAP_SYNC_REPL_1).expect("failed to parse ldap sync");

    // need to setup a fake ldap sync result.

    // What do we expect?
}

const TEST_LDAP_SYNC_REPL_1: &str = r#"
{
  "cookie": "aXBhLXN5bmNyZXBsLWthbmkuZGV2LmJsYWNraGF0cy5uZXQuYXU6Mzg5I2NuPWRpcmVjdG9yeSBtYW5hZ2VyOmNuPWFjY291bnRzLGRjPWRldixkYz1ibGFja2hhdHMsZGM9bmV0LGRjPWF1OihvYmplY3RDbGFzcz0qKSM3OA",
  "refresh_deletes": false,
  "entries": [
    {
      "entry_uuid": "ac600325-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "accounts"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac600326-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "users"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac600327-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "groups"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac600328-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "services"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac600329-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "computers"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac60032a-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=hostgroups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "hostgroups"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac60032b-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=ipservices,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "ipservices"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac60034b-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "uid=admin,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "Administrator"
          ],
          "gecos": [
            "Administrator"
          ],
          "gidNumber": [
            "8200000"
          ],
          "homeDirectory": [
            "/home/admin"
          ],
          "ipaNTHash": [
            "CVBguEizG80swI8sftaknw"
          ],
          "ipaNTSecurityIdentifier": [
            "S-1-5-21-148961183-2750130983-218252910-500"
          ],
          "ipaUniqueID": [
            "ad15f644-3498-11ed-95c3-5254006b0418"
          ],
          "krbExtraData": [
            "AAL4hSJjcm9vdC9hZG1pbkBERVYuQkxBQ0tIQVRTLk5FVC5BVQA"
          ],
          "krbLastAdminUnlock": [
            "20220915015504Z"
          ],
          "krbLastFailedAuth": [
            "20221007043105Z"
          ],
          "krbLastPwdChange": [
            "20220915015504Z"
          ],
          "krbLoginFailedCount": [
            "0"
          ],
          "krbPasswordExpiration": [
            "20221214015504Z"
          ],
          "krbPrincipalKey": [
            "MIIB1KADAgEBoQMCAQGiAwIBAaMDAgEBpIIBvDCCAbgwdKAbMBmgAwIBBKESBBBgeEMvRkhoVWphRX0iKXxCoVUwU6ADAgEUoUwESiAAuyt8szEUVLiWVjSTuUgbgCf8heFMeIhSmGTgJpwL50kddprbdeKuOYvyxepdAil/MqHs4qdqj54reDDqFW0T2bg1Iv9O1cZEMGSgGzAZoAMCAQShEgQQU2xOXT16V21hPFkzPClsJKFFMEOgAwIBE6E8BDoQALfdG+243xBQDt01+bFr46DcZnlHctoSyUQKw8I8FzvRE1LK9Ttl5qkkOHADpA7XSj1lQ2RFqBsSMHSgGzAZoAMCAQShEgQQay9XSC9tPDJJVjIwUDxFRKFVMFOgAwIBEqFMBEogADJjxICRFFzpOcsxMY3xVedF3IBd7qzsQJlSvShaeKwyhTBFI/wvVDtQq6ogWKlACUcAVk2N6p91VtRHHjxXVhKQvT0kt/KS7zBkoBswGaADAgEEoRIEEE5nNTh5SmgpZic0bDAmNUWhRTBDoAMCARGhPAQ6EAClGqBf9jZWixZo/evVMVH01NkI1VpR0fNrGyvtML78p5j6TAne5Nms/wj9BtVawuv+h+Gz1fjdfw"
          ],
          "krbPrincipalName": [
            "admin@DEV.BLACKHATS.NET.AU",
            "root@DEV.BLACKHATS.NET.AU"
          ],
          "loginShell": [
            "/bin/bash"
          ],
          "memberOf": [
            "cn=Add Configuration Sub-Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Add Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Host Enrollment,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify DNA Range,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify PassSync Managers Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read DNA Range,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read LDBM Database Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read PassSync Managers Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read Replication Changelog Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Remove Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Replication Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add krbPrincipalName to a Host,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Enroll a Host,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Certificates,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Enrollment Password,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Keytab,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Principals,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Write Replication Changelog Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=admins,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=trust admins,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "inetuser",
            "ipaNTUserAttrs",
            "ipaSshGroupOfPubKeys",
            "ipaobject",
            "ipasshuser",
            "krbprincipalaux",
            "krbticketpolicyaux",
            "person",
            "posixaccount",
            "top"
          ],
          "sn": [
            "Administrator"
          ],
          "uid": [
            "admin"
          ],
          "uidNumber": [
            "8200000"
          ],
          "userPassword": [
            "{PBKDF2_SHA256}AAAIAJ3EnyWJXp/ytIk6sqf1BbLO9fzObD3q5I4y2bRFfgAFVo6CaRAaZ7KPYzU6Y340VSUV4NGRRcBjeU8q+aoTOkuzQM91jl+xlCydiB0CjeIDZ0tGy4NmQUFzfg7+exsKhNk2MfUrHcaqfZBtT7Lkfei4Rk7810TQf3NlHIRO8K3egPQ8Ox52Upw1E5QGEKQmDOjrtLtOF5gbyFtR5wc0wUJfmMhd/g65GkqFIr5vbPan3kL3ZqMhh1rrj4ISi9Ui8P7E8GDicoJDPwPf6YD9D0dx6yk72GyiuYt6p2aGJWMY897xqgB+YMgPptiDPik22ExoBAoHeJNIzKjITc2ohLLn6RkCk4GcCwMVZmcxesl/T/OMeSkNvoOM1zy7ANsGbQeaLqpViJSV0xT5PJ6NoIKMU2pIP57Q17VAlYigtCPU"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac60034c-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=admins,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "admins"
          ],
          "description": [
            "Account administrators group"
          ],
          "gidNumber": [
            "8200000"
          ],
          "ipaNTSecurityIdentifier": [
            "S-1-5-21-148961183-2750130983-218252910-512"
          ],
          "ipaUniqueID": [
            "ad17b06a-3498-11ed-afaa-5254006b0418"
          ],
          "member": [
            "uid=admin,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "memberOf": [
            "cn=Add Configuration Sub-Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Add Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Host Enrollment,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify DNA Range,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify PassSync Managers Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read DNA Range,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read LDBM Database Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read PassSync Managers Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read Replication Changelog Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Remove Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Replication Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add krbPrincipalName to a Host,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Enroll a Host,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Certificates,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Enrollment Password,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Keytab,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Principals,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Write Replication Changelog Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "groupofnames",
            "ipaNTGroupAttrs",
            "ipaobject",
            "ipausergroup",
            "nestedGroup",
            "posixgroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac60034d-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=ipausers,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "ipausers"
          ],
          "description": [
            "Default group for all users"
          ],
          "ipaUniqueID": [
            "ad18f36c-3498-11ed-8668-5254006b0418"
          ],
          "member": [
            "uid=testuser,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "groupofnames",
            "ipaobject",
            "ipausergroup",
            "nestedgroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac60034e-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=editors,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "editors"
          ],
          "description": [
            "Limited admins who can edit other users"
          ],
          "gidNumber": [
            "8200002"
          ],
          "ipaNTSecurityIdentifier": [
            "S-1-5-21-148961183-2750130983-218252910-1002"
          ],
          "ipaUniqueID": [
            "ad191e00-3498-11ed-b143-5254006b0418"
          ],
          "objectClass": [
            "groupofnames",
            "ipantgroupattrs",
            "ipaobject",
            "ipausergroup",
            "nestedGroup",
            "posixgroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac60034f-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=ipaservers,cn=hostgroups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "ipaservers"
          ],
          "description": [
            "IPA server hosts"
          ],
          "ipaUniqueID": [
            "ad196cd4-3498-11ed-b143-5254006b0418"
          ],
          "member": [
            "fqdn=ipa-syncrepl-kani.dev.blackhats.net.au,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "memberOf": [
            "cn=Add Configuration Sub-Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Add Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify DNA Range,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify PassSync Managers Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read DNA Range,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read LDBM Database Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read PassSync Managers Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read Replication Changelog Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Remove Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Replication Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Write Replication Changelog Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "groupOfNames",
            "ipahostgroup",
            "ipaobject",
            "nestedGroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac60035d-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=cosTemplates,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "cosTemplates"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac600368-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=roles,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "roles"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac60036c-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=helpdesk,cn=roles,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "helpdesk"
          ],
          "description": [
            "Helpdesk"
          ],
          "memberOf": [
            "cn=Modify Group membership,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify Users and Reset passwords,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Change User password,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage User Certificates,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage User Principals,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify External Group Membership,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Group Membership,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Users,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "groupofnames",
            "nestedgroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac6003a8-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "krbprincipalname=ldap/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "ipaKrbPrincipalAlias": [
            "ldap/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "ipaUniqueID": [
            "ae89dcfc-3498-11ed-bd3d-5254006b0418"
          ],
          "krbCanonicalName": [
            "ldap/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "krbExtraData": [
            "AAK8hCJjcm9vdC9hZG1pbkBERVYuQkxBQ0tIQVRTLk5FVC5BVQA"
          ],
          "krbLastPwdChange": [
            "20220915014948Z"
          ],
          "krbLoginFailedCount": [
            "0"
          ],
          "krbPrincipalKey": [
            "MIICAqADAgEBoQMCAQGiAwIBAqMDAgEBpIIB6jCCAeYwV6FVMFOgAwIBEqFMBEogAIt4+Fj03b3othVOnbkGcFJre/qKqofqp4Cesx6wkgLEnLLV5SDqtc/xhJuiqO4NvQgEdebViuxzA7bXMkMFIe1xCD+nVN8rczBHoUUwQ6ADAgERoTwEOhAAoAUnjH3biykn+eZWsiN9f6Xp6ygrYwKxLEOQqph766yNlX1Dfr+0pjYEqmmnf2jq/bRFQlIcJW8wR6FFMEOgAwIBE6E8BDoQAJDDCOlnFEs25wcosS7KQBwv2hEmxtIaBVVAGRc947sl0AavVW1xZ7meuTwpTJoylGdNSTCIQF9cMFehVTBToAMCARShTARKIACdaPkMQSiKQ3nVoihxLeQDyRJ4Bz0E+vtDWZHLRncmmVbtmzzhSeTNk9+9uZZAUbv/mmy3y/FdvfgkBo/2buwaI3WnMXMiI1kwR6FFMEOgAwIBGaE8BDoQABAuW5X9h0BFx6+AkoqzUF1vi0bL99KJBj2ufVf3GvQ4RatalbeYvQZRLGiA+f6T0Tck5f3d4d3VMFehVTBToAMCARqhTARKIACBBonLVHBKTlVDNCVK7iDwojO5Vhtm7XG5D4NeCiM5zhqoPlXTa/7XzEENLRFG/jMC20cKGWzy9Y6iD2uJEfWbCjbVQGnIxIg"
          ],
          "krbPrincipalName": [
            "ldap/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "krbPwdPolicyReference": [
            "cn=Default Service Password Policy,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "krbTicketFlags": [
            "128"
          ],
          "managedBy": [
            "fqdn=ipa-syncrepl-kani.dev.blackhats.net.au,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "memberOf": [
            "cn=replication managers,cn=sysaccounts,cn=etc,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "ipakrbprincipal",
            "ipaobject",
            "ipaservice",
            "krbTicketPolicyAux",
            "krbprincipal",
            "krbprincipalaux",
            "pkiuser",
            "top"
          ],
          "userCertificate": [
            "MIIFsTCCBBmgAwIBAgIBCDANBgkqhkiG9w0BAQsFADA/MR0wGwYDVQQKDBRERVYuQkxBQ0tIQVRTLk5FVC5BVTEeMBwGA1UEAwwVQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTIyMDkxNTAxNTE1OFoXDTI0MDkxNTAxNTE1OFowUDEdMBsGA1UECgwUREVWLkJMQUNLSEFUUy5ORVQuQVUxLzAtBgNVBAMMJmlwYS1zeW5jcmVwbC1rYW5pLmRldi5ibGFja2hhdHMubmV0LmF1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1hu4DO2P6coC30ivQScItRA8TnliBr4Rf9vHcSMgFbJIUWD+VhfF5l42XXpAJU29kyaTWhMv0suC/youFQ0NKaVcuvUcPdd4bgcLjzHxNRMxUKXEuvffUzARV0KIdZoJQ1s8MT76mTgNmezJoqt8T+q0f5d/2J2jjEIbEC8V2igUR+YLHRahvRZZIYxZZ0hflZyUOtTiMa7sAhjGgbSPGp7QsErHTeoJ2J0R3EJWOvvGHkKgg69wSBZENEoyxlg/pk3aVXbFsIIkO5XooGE8b+EVm52xw9Uk0xDlWm0ZJuB6yRGs2Ntv/vBz0Q6QLJH3fK+fsWnCUutHNAQi2yA4OwIDAQABo4ICJTCCAiEwHwYDVR0jBBgwFoAU3r1esNaYPVZc1ckSKy7uVspCunowRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vaXBhLWNhLmRldi5ibGFja2hhdHMubmV0LmF1L2NhL29jc3AwDgYDVR0PAQH/BAQDAgTwMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjB/BgNVHR8EeDB2MHSgPKA6hjhodHRwOi8vaXBhLWNhLmRldi5ibGFja2hhdHMubmV0LmF1L2lwYS9jcmwvTWFzdGVyQ1JMLmJpbqI0pDIwMDEOMAwGA1UECgwFaXBhY2ExHjAcBgNVBAMMFUNlcnRpZmljYXRlIEF1dGhvcml0eTAdBgNVHQ4EFgQUqhFargNcWnY/crbOldPRe751v2UwgeYGA1UdEQSB3jCB24ImaXBhLXN5bmNyZXBsLWthbmkuZGV2LmJsYWNraGF0cy5uZXQuYXWgUAYKKwYBBAGCNxQCA6BCDEBsZGFwL2lwYS1zeW5jcmVwbC1rYW5pLmRldi5ibGFja2hhdHMubmV0LmF1QERFVi5CTEFDS0hBVFMuTkVULkFVoF8GBisGAQUCAqBVMFOgFhsUREVWLkJMQUNLSEFUUy5ORVQuQVWhOTA3oAMCAQGhMDAuGwRsZGFwGyZpcGEtc3luY3JlcGwta2FuaS5kZXYuYmxhY2toYXRzLm5ldC5hdTANBgkqhkiG9w0BAQsFAAOCAYEAO5YJykFv9SUy9UuEn8sF5lzghT+kJUEZr1Tzf9JArSDSE91j74428UmwgJjWa96G04/cDBg8vkivno8432mFnuLghn5oiIRthCVu125gWkZZ22MPranNYbNtoKPerqtRfEcQdxT9bg9TkX4F5xxuYZxt63KFQ4FFi7K8SKm28xnzddCVrq7ZL8/5Tk87rNdPL35FYS+uDBO8kFGIscdudPbSd64BWa5oRg97pAzDfR8EmSOiYD9PHJ7PgoilkKdfp1IsY4mYs5fJ2/U946/FvCXznmLgvqJf5dmt6JqFh3ctfiC28/c+LQydEacW7ud76wJdr/FCos3TI1zG8CI5vu0OFt8CZvZ6z9ZyH7UgSQl6avvXY+oEeFEruJ3tu2gP82/bXIzjs31IZKkN/g/TaD8xY5tpRAsfKfQ/8yKQvMtwl/ghE0/alYlHLBW4sXUX4lEkwZDwW5vQc6v86LapRfW/qvVrXItdpgJ79Z/jiYN9bB7MyUYis4rUBwU8ZrFX"
          ]
        }
      }
    },
    {
      "entry_uuid": "ac6003aa-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "fqdn=ipa-syncrepl-kani.dev.blackhats.net.au,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "ipa-syncrepl-kani.dev.blackhats.net.au"
          ],
          "fqdn": [
            "ipa-syncrepl-kani.dev.blackhats.net.au"
          ],
          "ipaSshPubKey": [
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL2s1FMFa4FwRDjqw8gbHgCpIaOvhQtBQZ9VcTAvpTHC/CIewmKgLYffnQklJOM9Npn2ShSOZwNpQYrwalVEeIA=",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHTGOifacjiocH68IwplT7LOecMPzIyvZxeR5u9v4tnc",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDsXHlwhgSxhSN3eAlyWnqcD4pnrBDH3msyWfFM/jeQjz7GeZEjvGv41t4czZWEHTHsi4UeHAuV865eGYSBmCtdJZuO/IK69oT4wVgnp6ZJSzfAMeVerNzF+W4mnvpyEsRjydhDv3lkWdYW5E6cfoE/5363p0N6VKEZP5zNOomTHm4qveFU+MBqJaGCDjGpSfhnHpeVi99ZtURitA/azs+6Mdzu/IDUR3xHeNaWcfISqhOM3UhNi5R7wcCjYZxqOfa1cx/rGzMAuRFUM56J2JvCGY9r5bKQHYApejLSHGu6v1c4r14rdA9/EcA1W3atKbUjQxYL3IIkx+tQR6MGV2Vks9qjAQQKnQL2893zRYZuz7Hlwi6Z9/4p6bIWOxkQk9VJiJMjIIMmi1/fBn8z+DZu2OJ7kgFUkPpKCZ7mDpWWdkY9zd2JNOHpbyIDHRwH4GtWSudQ1kZHqLN2osrbLUsJjbevY7qy31EHY1RJoUL/f7igf/1HXlUyQ39vWyzT+Qs="
          ],
          "ipaUniqueID": [
            "aeb18a36-3498-11ed-95c3-5254006b0418"
          ],
          "krbCanonicalName": [
            "host/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "krbExtraData": [
            "AAK8hCJjcm9vdC9hZG1pbkBERVYuQkxBQ0tIQVRTLk5FVC5BVQA"
          ],
          "krbLastPwdChange": [
            "20220915014948Z"
          ],
          "krbPrincipalKey": [
            "MIICAqADAgEBoQMCAQGiAwIBAqMDAgEBpIIB6jCCAeYwV6FVMFOgAwIBEqFMBEogALjVV59CiovQ9czlBymqalSlY9UIcjjWSwbPj9vxwDRxc/0mQ0CDxqnPJjeu5aC2P8FiDw2ODF6cYoR1hWuRoAfse7UWW8ef/DBHoUUwQ6ADAgERoTwEOhAAJ7pUeI2zR6XMvyygR5/iP5KDYKtNnZyqNG6GWeP08ub440XP2f2d7N1JIS4SDbzevqzEIfMX7EYwR6FFMEOgAwIBE6E8BDoQAB2rw9U1hf0QntlzrjJ3f3iTqw91szfOZ87rgKSixBwfk/U1WXrN2OMVd15b+SsI2VQ0dFCBKzdKMFehVTBToAMCARShTARKIAAMOAEIC+bUW8fMp07LW5L/2VlK3HoXnoH48IHrp9ML68aLNxnNi5iJuqmWhFMO3sqCO6NCK9sizBWoUEcAKaU7bMq/3vCYxj0wR6FFMEOgAwIBGaE8BDoQAPOFfZmuqeSYyhuOdauIEqTY4l17K7rTxSQPauAZKZ1aoDmBmJzp1lD2wtzOzES+oJ9kPdmebpIlMFehVTBToAMCARqhTARKIAC3M5qXIO702h2Ry4QteGF81BcZQcnLQTAEbEfgGerhCyXCfgKxACK6SzLOUOCo6d4Tr37mVwvAKivMrTprhvWeJiBfkM9ObXQ"
          ],
          "krbPrincipalName": [
            "host/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "krbPwdPolicyReference": [
            "cn=Default Host Password Policy,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "krbTicketFlags": [
            "128"
          ],
          "managedBy": [
            "fqdn=ipa-syncrepl-kani.dev.blackhats.net.au,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "memberOf": [
            "cn=Add Configuration Sub-Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Add Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify DNA Range,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify PassSync Managers Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read DNA Range,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read LDBM Database Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read PassSync Managers Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read Replication Changelog Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Remove Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Replication Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Write Replication Changelog Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=ipaservers,cn=hostgroups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "ipaSshGroupOfPubKeys",
            "ipahost",
            "ipaobject",
            "ipaservice",
            "ipasshhost",
            "krbprincipal",
            "krbprincipalaux",
            "krbticketpolicyaux",
            "nshost",
            "pkiuser",
            "top"
          ],
          "serverHostName": [
            "ipa-syncrepl-kani"
          ]
        }
      }
    },
    {
      "entry_uuid": "ffd25150-3498-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "krbprincipalname=dogtag/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "ipaKrbPrincipalAlias": [
            "dogtag/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "ipaUniqueID": [
            "010aac04-3499-11ed-94f0-5254006b0418"
          ],
          "krbCanonicalName": [
            "dogtag/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "krbExtraData": [
            "AAJHhSJjcm9vdC9hZG1pbkBERVYuQkxBQ0tIQVRTLk5FVC5BVQA"
          ],
          "krbLastPwdChange": [
            "20220915015207Z"
          ],
          "krbLoginFailedCount": [
            "0"
          ],
          "krbPrincipalKey": [
            "MIICAqADAgEBoQMCAQGiAwIBAqMDAgEBpIIB6jCCAeYwV6FVMFOgAwIBEqFMBEogAOqe66hXnldEGz/s/2I89YygoskwmDCeiyIshuzMQCYRAYzvj/Za0hoaOGQ14WmmLiCU5sFlDGP+iNruTCTJWcbS2ceEhe3knDBHoUUwQ6ADAgERoTwEOhAAaqby3NxjVoP0NbbrerSWisui35G5NmTtMbf5LXirjYzRJEqOry551K7KRfOeINh5iQS7xupe+LowR6FFMEOgAwIBE6E8BDoQAKIln3mXSKY3I3pVpv0Nl7gJwSTMiMjuiTB5xU8EROjn/7hFVk7oelCcN3s2r9xhTlHS3MGVvPCqMFehVTBToAMCARShTARKIAD7caE8fup28Qo58twN/X344JGlpjii3iPIYEZ9D7+wb7jFhmhDnOtm+9dzT99zul0p8HvbIHcvRrP6aFmgV/KChGssKv8WRxQwR6FFMEOgAwIBGaE8BDoQAExsq/3MeNsYqGuuHK3hkFJhngOcjz8u3SqlpzLwTbol3/RSGi4Z0ajVqX1Oo26xxt3IQSduRZs+MFehVTBToAMCARqhTARKIAA/+X0NWyL8DTm8NimTtqt4qGDuIKnx666tpiao0avRHMdntqj+47nFT2mhS4j1FustPi5TDlmBm+QyaEqLrCRfNcSBIxxuq6c"
          ],
          "krbPrincipalName": [
            "dogtag/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "krbPwdPolicyReference": [
            "cn=Default Service Password Policy,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "krbTicketFlags": [
            "128"
          ],
          "managedBy": [
            "fqdn=ipa-syncrepl-kani.dev.blackhats.net.au,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "ipakrbprincipal",
            "ipaobject",
            "ipaservice",
            "krbTicketPolicyAux",
            "krbprincipal",
            "krbprincipalaux",
            "pkiuser",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "02cd410c-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "krbprincipalname=HTTP/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "ipaKrbPrincipalAlias": [
            "HTTP/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "ipaUniqueID": [
            "0753f7aa-3499-11ed-be02-5254006b0418"
          ],
          "krbCanonicalName": [
            "HTTP/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "krbExtraData": [
            "AAJRhSJjSFRUUC9pcGEtc3luY3JlcGwta2FuaS5kZXYuYmxhY2toYXRzLm5ldC5hdUBERVYuQkxBQ0tIQVRTLk5FVC5BVQA"
          ],
          "krbLastPwdChange": [
            "20220915015217Z"
          ],
          "krbPrincipalKey": [
            "MIIB1KADAgEBoQMCAQGiAwIBAaMDAgEBpIIBvDCCAbgwdKAbMBmgAwIBBKESBBBKPD5dWTdzSVRtP3EwU1hRoVUwU6ADAgEUoUwESiAAYwIymfpDp5vJdIyXzk479qv5VX6Mc6+nLly59bWI3EYVY2epAoeRO8T5KGZXG90WN36+fIMIvfe1gZSpplsdmJhh9/1LnDrIMGSgGzAZoAMCAQShEgQQKDouQW1hWH0pQzk8KClMJ6FFMEOgAwIBE6E8BDoQAFSkARWtl5FySsIwStmACSPGwm4Hq/r+M6vrQfOgw6V7Nwm4uX4dkgyyuPmQGj/yGLnjRo1T5UycMHSgGzAZoAMCAQShEgQQLEZHJitYR0h7akdxTWxHfKFVMFOgAwIBEqFMBEogAND/+/LRxdQZjoA/B6axDQMlV3DObQ+EBW+0mgbWfBZKwvbc7vKzlxLxfQViOgGOmQcqb5R1Xbw3Yg8OlFuhD2k0+5IiOtFUgzBkoBswGaADAgEEoRIEEFguXEBfNkQ8TmpfcjVYLT6hRTBDoAMCARGhPAQ6EACHcWgiZ3MkRqCO1cSiYVGDmtAEjWv/2rPS3Sg9qy8/UWJtvp2w2bRml80H7yM7e4JK+lQHhvlu8A"
          ],
          "krbPrincipalName": [
            "HTTP/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "krbPwdPolicyReference": [
            "cn=Default Service Password Policy,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "managedBy": [
            "fqdn=ipa-syncrepl-kani.dev.blackhats.net.au,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "ipakrbprincipal",
            "ipaobject",
            "ipaservice",
            "krbprincipal",
            "krbprincipalaux",
            "krbticketpolicyaux",
            "pkiuser",
            "top"
          ],
          "userCertificate": [
            "MIIFzzCCBDegAwIBAgIBCTANBgkqhkiG9w0BAQsFADA/MR0wGwYDVQQKDBRERVYuQkxBQ0tIQVRTLk5FVC5BVTEeMBwGA1UEAwwVQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTIyMDkxNTAxNTIxOFoXDTI0MDkxNTAxNTIxOFowUDEdMBsGA1UECgwUREVWLkJMQUNLSEFUUy5ORVQuQVUxLzAtBgNVBAMMJmlwYS1zeW5jcmVwbC1rYW5pLmRldi5ibGFja2hhdHMubmV0LmF1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwheTBXcywPA3FMnikuqdrqIE8JkQRr+2s2nuRAnAhSPVL5wvo9cTWDHUxsHNjpCtlVigHfAdAH9/97VEUhhUWKeAF0On6HBUS8JDN+lLMKNgtKgtK43/6lIeTRXjIamgtjGI5uZzL50Y3dmL62pDnMtI0HfNdp6NE4STmUenvSJ3j5o3K33Vy9OxksIJzyIoqQJ28oYqB2kQh8GyKhc3oG6jHDYYN8GbZpg1wGiZHFtCtCrs0F9MmUdXyr5mOWaNjNVFUqJG603T9qwz9DiOGS8RSeDO9UP8ouiU3m0XRJoXAJCj/WmdQuLsr3mOKe/o6IQ7oDHjqvl48K8Ec6C2AQIDAQABo4ICQzCCAj8wHwYDVR0jBBgwFoAU3r1esNaYPVZc1ckSKy7uVspCunowRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vaXBhLWNhLmRldi5ibGFja2hhdHMubmV0LmF1L2NhL29jc3AwDgYDVR0PAQH/BAQDAgTwMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjB/BgNVHR8EeDB2MHSgPKA6hjhodHRwOi8vaXBhLWNhLmRldi5ibGFja2hhdHMubmV0LmF1L2lwYS9jcmwvTWFzdGVyQ1JMLmJpbqI0pDIwMDEOMAwGA1UECgwFaXBhY2ExHjAcBgNVBAMMFUNlcnRpZmljYXRlIEF1dGhvcml0eTAdBgNVHQ4EFgQUBt9zuYl/V2blQ1BEqHE5NlvqBCEwggEDBgNVHREEgfswgfiCJmlwYS1zeW5jcmVwbC1rYW5pLmRldi5ibGFja2hhdHMubmV0LmF1ghtpcGEtY2EuZGV2LmJsYWNraGF0cy5uZXQuYXWgUAYKKwYBBAGCNxQCA6BCDEBIVFRQL2lwYS1zeW5jcmVwbC1rYW5pLmRldi5ibGFja2hhdHMubmV0LmF1QERFVi5CTEFDS0hBVFMuTkVULkFVoF8GBisGAQUCAqBVMFOgFhsUREVWLkJMQUNLSEFUUy5ORVQuQVWhOTA3oAMCAQGhMDAuGwRIVFRQGyZpcGEtc3luY3JlcGwta2FuaS5kZXYuYmxhY2toYXRzLm5ldC5hdTANBgkqhkiG9w0BAQsFAAOCAYEAtwCyLts3iTZEWuE83VoJqkTkzc04YvwVXPQamyu7IwbUGsrFZPxj9A1Binv9/ZtJw27P+LL8xFbCMMuvGV33XlDtdznV/511m+62QzYGXf8xKitxZiWupgwpm6/9yPrEoXTFp0fZqENFBbOgdIlXZTocctu/rNMlWN5prCEmaE132l0jG1+9y/qxQI7lWIIe7fHvV9GWmPATpf7YghzPyQbxRUNdgenzboJtcqxHqOmoOPDFFb2EzI+KbvE42UF3O/VUGppECFaKw2yJK3O/A2aa/6lhmgmP1U3783lw9nFVem5Se5Br0m4k3KTiv1vzjqSq7e2s0gblnhte8ZvoWz8GDxYin83c730muRhsbv/DBrbDiJCYzfftkgNKy+Ab4h0Z82SZ5MjGbyR9svTV8UQzIT3bKeIz1gLXHPDCYyJnXiU5rrCwSGtt5JAD3WdZCo+DO+g7PFpcfs9dhPaBbRiiOu0PFnqrlV5FNpPS1NJxJFgUoU1TH8CWeEQz2l5A"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a910-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=Default Host Password Policy,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "Default Host Password Policy"
          ],
          "krbMaxPwdLife": [
            "0"
          ],
          "krbMinPwdLife": [
            "0"
          ],
          "krbPwdFailureCountInterval": [
            "0"
          ],
          "krbPwdHistoryLength": [
            "0"
          ],
          "krbPwdLockoutDuration": [
            "0"
          ],
          "krbPwdMaxFailure": [
            "0"
          ],
          "krbPwdMinDiffChars": [
            "0"
          ],
          "krbPwdMinLength": [
            "0"
          ],
          "objectClass": [
            "krbPwdPolicy",
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a911-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=Default Service Password Policy,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "Default Service Password Policy"
          ],
          "krbMaxPwdLife": [
            "0"
          ],
          "krbMinPwdLife": [
            "0"
          ],
          "krbPwdFailureCountInterval": [
            "0"
          ],
          "krbPwdHistoryLength": [
            "0"
          ],
          "krbPwdLockoutDuration": [
            "0"
          ],
          "krbPwdMaxFailure": [
            "0"
          ],
          "krbPwdMinDiffChars": [
            "0"
          ],
          "krbPwdMinLength": [
            "0"
          ],
          "objectClass": [
            "krbPwdPolicy",
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a915-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=cosTemplates,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "cosTemplates"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a916-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=Default Password Policy,cn=cosTemplates,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "Default Password Policy"
          ],
          "cosPriority": [
            "10000000000"
          ],
          "krbPwdPolicyReference": [
            "cn=Default Host Password Policy,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "cosTemplate",
            "extensibleObject",
            "krbContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a918-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=cosTemplates,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "cosTemplates"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a919-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=Default Password Policy,cn=cosTemplates,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "Default Password Policy"
          ],
          "cosPriority": [
            "10000000000"
          ],
          "krbPwdPolicyReference": [
            "cn=Default Service Password Policy,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "cosTemplate",
            "extensibleObject",
            "krbContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a957-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=User Administrator,cn=roles,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "User Administrator"
          ],
          "description": [
            "Responsible for creating Users and Groups"
          ],
          "memberOf": [
            "cn=Group Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Manage subordinate ID,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Stage User Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Subordinate ID Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Groups,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Stage User,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add User to default group,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Users,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Change User password,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Subordinate Ids,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage User Certificates,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage User Principals,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage User SSH Public Keys,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify External Group Membership,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Group Membership,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Groups,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Preserved Users,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Stage User,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify User RDN,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Users,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Preserve User,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read Preserved Users,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read Radius Servers,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read Stage User password,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read Stage Users,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read UPG Definition,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read User Kerberos Login Attributes,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Groups,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Stage User,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Subordinate Ids,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Users,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove preserved User,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Reset Preserved User password,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Undelete User,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Unlock User,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=User Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "groupofnames",
            "nestedgroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a958-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=IT Specialist,cn=roles,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "IT Specialist"
          ],
          "description": [
            "IT Specialist"
          ],
          "memberOf": [
            "cn=Automount Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Host Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Host Group Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Retrieve Certificates from the CA,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Revoke Certificate,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Service Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Automount Keys,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Automount Locations,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Automount Maps,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Hostgroups,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Hosts,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Service Delegations,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Services,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add krbPrincipalName to a Host,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Enroll a Host,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Certificates,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Enrollment Password,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Keytab Permissions,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Keytab,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Principals,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host SSH Public Keys,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Service Keytab Permissions,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Service Keytab,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Service Principals,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Automount Keys,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Automount Maps,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Hostgroup Membership,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Hostgroups,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Hosts,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Service Delegation Membership,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Services,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read Service Delegations,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Automount Keys,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Automount Locations,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Automount Maps,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Hostgroups,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Hosts,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Service Delegations,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Services,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "groupofnames",
            "nestedgroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a959-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=IT Security Specialist,cn=roles,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "IT Security Specialist"
          ],
          "description": [
            "IT Security Specialist"
          ],
          "memberOf": [
            "cn=HBAC Administrator,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Netgroups Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Sudo Administrator,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add HBAC Rule,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add HBAC Service Groups,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add HBAC Services,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Netgroups,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Sudo Command Group,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Sudo Command,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Sudo rule,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Delete HBAC Rule,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Delete HBAC Service Groups,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Delete HBAC Services,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Delete Sudo Command Group,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Delete Sudo Command,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Delete Sudo rule,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage HBAC Rule Membership,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage HBAC Service Group Membership,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Sudo Command Group Membership,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify HBAC Rule,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Netgroup Membership,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Netgroups,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Sudo Command Group,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Sudo Command,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Sudo rule,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Netgroups,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "groupofnames",
            "nestedgroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a95a-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=Security Architect,cn=roles,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "Security Architect"
          ],
          "description": [
            "Security Architect"
          ],
          "memberOf": [
            "cn=Add Configuration Sub-Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Add Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Delegation Administrator,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify DNA Range,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify PassSync Managers Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Modify Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Password Policy Administrator,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read DNA Range,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read LDBM Database Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read PassSync Managers Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Read Replication Changelog Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Remove Replication Agreements,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Replication Administrators,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Group Password Policy costemplate,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Group Password Policy,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Privileges,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add Roles,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Delete Group Password Policy costemplate,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Delete Group Password Policy,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Group Password Policy costemplate,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Group Password Policy,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Privilege Membership,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Privileges,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Role Membership,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Modify Roles,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read Group Password Policy costemplate,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read Group Password Policy,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Privileges,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove Roles,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Write IPA Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Write IPA Configuration,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Write Replication Changelog Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "groupofnames",
            "nestedgroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a95b-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=Enrollment Administrator,cn=roles,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "Enrollment Administrator"
          ],
          "description": [
            "Enrollment Administrator responsible for client(host) enrollment"
          ],
          "memberOf": [
            "cn=Host Enrollment,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add krbPrincipalName to a Host,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Enroll a Host,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Certificates,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Enrollment Password,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Keytab,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage Host Principals,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "groupofnames",
            "nestedgroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a965-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=trust admins,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "trust admins"
          ],
          "description": [
            "Trusts administrators group"
          ],
          "ipaUniqueID": [
            "0f233c48-3499-11ed-8e23-5254006b0418"
          ],
          "member": [
            "uid=admin,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "groupofnames",
            "ipaobject",
            "ipausergroup",
            "nestedgroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a969-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=views,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "views"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a96d-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=subids,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "subids"
          ],
          "objectClass": [
            "nsContainer",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "0c56a96e-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=Subordinate ID Selfservice User,cn=roles,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "Subordinate ID Selfservice User"
          ],
          "description": [
            "User that can self-request subordiante ids"
          ],
          "memberOf": [
            "cn=Self-service subordinate ID,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=Subordinate ID Selfservice Users,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "groupofnames",
            "nestedgroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "5d669e0f-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "krbprincipalname=DNS/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "ipaUniqueID": [
            "5eef7106-3499-11ed-b9b6-5254006b0418"
          ],
          "krbCanonicalName": [
            "DNS/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "krbExtraData": [
            "AALkhSJjcm9vdC9hZG1pbkBERVYuQkxBQ0tIQVRTLk5FVC5BVQA"
          ],
          "krbLastPwdChange": [
            "20220915015444Z"
          ],
          "krbLoginFailedCount": [
            "0"
          ],
          "krbPrincipalKey": [
            "MIICAqADAgEBoQMCAQGiAwIBAqMDAgEBpIIB6jCCAeYwV6FVMFOgAwIBEqFMBEogAKadOfupjB5yb9MTZZqmM9CZoBJKpjByYaD66vmPQhiF0rncekqUZO/8ExZ+6Gasu1bIasBoAvjuNfYRNBAy0Zf7GrytjhJYKDBHoUUwQ6ADAgERoTwEOhAAgGBO1kFCX+Xum0dUbkOIhdP2T8Aj/nNpKDfo1+oRMYGJrDeTRBTSEsJZz9+tgWyD+gEY7jkrVZAwR6FFMEOgAwIBE6E8BDoQACR5EI6G6Zhkef34HovcuEZlpGtGfTZeoKASB/aDZrPhKpm+BjmnP0moUG1l3Ne+U4CbND3qz6K8MFehVTBToAMCARShTARKIADcrwredJSxyDMPxvInS1CtPNdGKy0cxOTb7p9oqqY5K9Aumm19H6P9MSIRC3q3s1irVhggZ9uPdfKMvHjzfj7o0gxO3r0w2VowR6FFMEOgAwIBGaE8BDoQAFU/tM7D+PBngTWJYD+g2FopzWjMLnjOsC4B2Bj5J/Z2rCKqqg/xBR0W6hFVjJ9L6gaXG3N8Dxk1MFehVTBToAMCARqhTARKIADkQ/J7BJhs0w6cCdKW/hS61eeJKwkNju/CCNBn/WA+93NlOmCgGNnipzkzGG8XiVJ/PbRQ/Lc9mwBYmhuZ606kwRvgSpZWFYM"
          ],
          "krbPrincipalName": [
            "DNS/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "krbPwdPolicyReference": [
            "cn=Default Service Password Policy,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "krbTicketFlags": [
            "128"
          ],
          "managedBy": [
            "fqdn=ipa-syncrepl-kani.dev.blackhats.net.au,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "memberOf": [
            "cn=DNS Servers,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add DNS Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage DNSSEC keys,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage DNSSEC metadata,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read DNS Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read DNS Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read DNS Servers Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove DNS Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Update DNS Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Write DNS Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "ipaobject",
            "ipaservice",
            "krbTicketPolicyAux",
            "krbprincipal",
            "krbprincipalaux",
            "pkiuser",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "5d669e18-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "krbprincipalname=ipa-dnskeysyncd/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "ipaUniqueID": [
            "67bcb154-3499-11ed-b557-5254006b0418"
          ],
          "krbCanonicalName": [
            "ipa-dnskeysyncd/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "krbExtraData": [
            "AALzhSJjcm9vdC9hZG1pbkBERVYuQkxBQ0tIQVRTLk5FVC5BVQA"
          ],
          "krbLastPwdChange": [
            "20220915015459Z"
          ],
          "krbLoginFailedCount": [
            "0"
          ],
          "krbPrincipalKey": [
            "MIICAqADAgEBoQMCAQGiAwIBAqMDAgEBpIIB6jCCAeYwV6FVMFOgAwIBEqFMBEogAFa7Sp3bdrbaiQe70zCSQbMgcyCINfyrect5SVfT12CpqcEgQAIePmpXl27NiZkWHq15jl2TwWr2iEV9M5P/N8a/OXKsg8zd0zBHoUUwQ6ADAgERoTwEOhAAGCJuZzCbpGsjCHOn7WDxSvT+/+M69goL/8n6tU3pDWhg+kmFigJKAyvGAJ65znpDOYQOhrSm8cIwR6FFMEOgAwIBE6E8BDoQAA1H2x5/e0M7PZUFQz+FGC/wvoEnRBZSTss3KZrmxJ29KEK+0isSSsbMx8EzgNHlkqec5uva1aRQMFehVTBToAMCARShTARKIAAHLvDl7XzuhsPjx1BNt2MLkpvZCjqgGytapi+r76VG9pgjD67zdXvsEknn1LedR3jUzonDiXpWxGG5x+CZlXzNFYKu1bLVHOcwR6FFMEOgAwIBGaE8BDoQAJmC/mDbPNS7Pu09PPfOMyV3YvceWTncbNYGn2/PfyG3ixyBytUXgXpO39Fg47wwPvRaJjukhgT4MFehVTBToAMCARqhTARKIADEyjJA+Ovq57s/2SZL8P7pZ/W8YpkICp2Lhh+1QGq0qvfL0eBzGa+KIoofqnlkznYcbU5nzwol2esnSBTL7rbzgTqW4I+Neqo"
          ],
          "krbPrincipalName": [
            "ipa-dnskeysyncd/ipa-syncrepl-kani.dev.blackhats.net.au@DEV.BLACKHATS.NET.AU"
          ],
          "krbPwdPolicyReference": [
            "cn=Default Service Password Policy,cn=services,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "krbTicketFlags": [
            "128"
          ],
          "managedBy": [
            "fqdn=ipa-syncrepl-kani.dev.blackhats.net.au,cn=computers,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "memberOf": [
            "cn=DNS Servers,cn=privileges,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Add DNS Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage DNSSEC keys,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Manage DNSSEC metadata,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read DNS Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read DNS Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Read DNS Servers Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Remove DNS Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Update DNS Entries,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au",
            "cn=System: Write DNS Configuration,cn=permissions,cn=pbac,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "ipaobject",
            "ipaservice",
            "krbTicketPolicyAux",
            "krbprincipal",
            "krbprincipalaux",
            "pkiuser",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "6a838c0b-3499-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=Default SMB Group,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "Default SMB Group"
          ],
          "description": [
            "Fallback group for primary group RID, do not add users to this group"
          ],
          "gidNumber": [
            "8200001"
          ],
          "ipaNTSecurityIdentifier": [
            "S-1-5-21-148961183-2750130983-218252910-1001"
          ],
          "ipaUniqueID": [
            "6ac2d0ea-3499-11ed-8b34-5254006b0418"
          ],
          "objectClass": [
            "ipantgroupattrs",
            "ipaobject",
            "posixgroup",
            "top"
          ]
        }
      }
    },
    {
      "entry_uuid": "babb8302-43a1-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "uid=testuser,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "Test User"
          ],
          "displayName": [
            "Test User"
          ],
          "gecos": [
            "Test User"
          ],
          "gidNumber": [
            "12345"
          ],
          "givenName": [
            "Test"
          ],
          "homeDirectory": [
            "/home/testuser"
          ],
          "initials": [
            "TU"
          ],
          "ipaNTHash": [
            "iEb36u6PsRetBr3YMLdYbA"
          ],
          "ipaNTSecurityIdentifier": [
            "S-1-5-21-148961183-2750130983-218252910-1004"
          ],
          "ipaUniqueID": [
            "d939d566-43a1-11ed-85aa-5254006b0418"
          ],
          "ipaUserAuthType": [
            "otp",
            "password"
          ],
          "krbCanonicalName": [
            "testuser@DEV.BLACKHATS.NET.AU"
          ],
          "krbExtraData": [
            "AAKuqj9jcm9vdC9hZG1pbkBERVYuQkxBQ0tIQVRTLk5FVC5BVQA"
          ],
          "krbLastAdminUnlock": [
            "20221007042726Z"
          ],
          "krbLastPwdChange": [
            "20221007042726Z"
          ],
          "krbLoginFailedCount": [
            "0"
          ],
          "krbPasswordExpiration": [
            "20221007042726Z"
          ],
          "krbPrincipalKey": [
            "MIIB1KADAgEBoQMCAQGiAwIBAqMDAgEBpIIBvDCCAbgwdKAbMBmgAwIBBKESBBAyd1FKPzBOfVwpMndBIUYzoVUwU6ADAgEUoUwESiAA08e/f13GWN0CXe7CQKbgKZi5huKImq5jD0FK304F3VqZDZcgH/vNK4jb4M5bliYSVTsnRJ7AHUWalPW1HDBd9KSLWFyoZMzkMGSgGzAZoAMCAQShEgQQV2Q/Z0d6RTplNmJnWiVGfKFFMEOgAwIBE6E8BDoQAOnA4dDmKA2oTh4hZnDf1/9ZVi24CQHpwUELHvAxjCE5WGI/X3AdTW/qoQ1hMijXZAfLrEILwu30MHSgGzAZoAMCAQShEgQQSWB1Xy05Wi4kb29jS005dqFVMFOgAwIBEqFMBEogAG/2TTXU4SlNkL2hnq528DrE6NPQVGYWu8q56UrxIqP3W+3Uyni93l3bKDbILoRl7+zpe6ten2dwV99MViDcuQ+1ZwekeME8xDBkoBswGaADAgEEoRIEEE4yL0ZcOGNzRFInXVs4VS+hRTBDoAMCARGhPAQ6EADdh6TBk9LTIBK/KhMLxeKATrQu9mk2y3GcmgvPU+HwKoEj3lWYJ4SuTc730mUb4KQsrS6+8qXilg"
          ],
          "krbPrincipalName": [
            "testuser@DEV.BLACKHATS.NET.AU"
          ],
          "loginShell": [
            "/bin/sh"
          ],
          "mail": [
            "testuser@dev.blackhats.net.au"
          ],
          "memberOf": [
            "cn=ipausers,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "mepManagedEntry": [
            "cn=testuser,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "inetorgperson",
            "inetuser",
            "ipaSshGroupOfPubKeys",
            "ipantuserattrs",
            "ipaobject",
            "ipasshuser",
            "ipauserauthtypeclass",
            "krbprincipalaux",
            "krbticketpolicyaux",
            "mepOriginEntry",
            "organizationalperson",
            "person",
            "posixaccount",
            "top"
          ],
          "sn": [
            "User"
          ],
          "uid": [
            "testuser"
          ],
          "uidNumber": [
            "8200004"
          ],
          "userPassword": [
            "{PBKDF2_SHA256}AAAIAEfAyPF34PDdETxzWnCQQN6Erz+TahCtmHixjbOPOb3skMmQzFCn5+18hevv/UHgvM1wUk7bZeKdxX6WJRLb5cEQR7rmv5HEX20pJl4tPwuW0uN15qX2pVEAwYbiKdw7NccxB0q1f5djc1NarmOYZoybpmmwclDug3WOa0+p0DkZlu5Q5gjX8V6DizlUjt38BV1itEGy16jU0rHFLxN4JrTXD9+j42Ie/6M+QvL+Tp35ToyMQFikCSN6D3nsvmWoM+4mKJTOjBtEXfK1zXjcuR8yXU2ajOhmcZP+LO1xIJGyPtJG1w5cjuK1/s4vn1UjtMayVzjiPisGxPinFmWVyI00mMKA2fVDuQOTnMER5grpDnMDUl1mAsZwKq3JXXq/1JJKY08KblhCmllo2dPforwAkkvzewN+c7Xp6W6DiHA8"
          ]
        }
      }
    },
    {
      "entry_uuid": "babb8306-43a1-11ed-a50d-919b4b1a5ec0",
      "state": "Add",
      "entry": {
        "dn": "cn=testuser,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
        "attrs": {
          "cn": [
            "testuser"
          ],
          "description": [
            "User private group for testuser"
          ],
          "gidNumber": [
            "8200004"
          ],
          "ipaUniqueID": [
            "d944a112-43a1-11ed-85aa-5254006b0418"
          ],
          "mepManagedBy": [
            "uid=testuser,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
          ],
          "objectClass": [
            "ipaobject",
            "mepManagedEntry",
            "posixgroup",
            "top"
          ]
        }
      }
    }
  ],
  "delete_uuids": [],
  "present_uuids": []
}
"#;

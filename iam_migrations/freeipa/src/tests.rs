use std::collections::HashMap;
use crate::process_ipa_sync_result;
use kanidm_proto::scim_v1::{ScimSyncRequest, ScimSyncState};

use ldap3_client::LdapSyncRepl;

#[tokio::test]
async fn test_ldap_to_scim() {
    let _ = tracing_subscriber::fmt::try_init();

    let sync_request: LdapSyncRepl =
        serde_json::from_str(TEST_LDAP_SYNC_REPL_1).expect("failed to parse ldap sync");

    let expect_scim_request: ScimSyncRequest =
        serde_json::from_str(TEST_SCIM_SYNC_REPL_1).expect("failed to parse scim sync");

    let entry_config_map = HashMap::default();

    let scim_sync_request = process_ipa_sync_result(ScimSyncState::Refresh, sync_request, &entry_config_map)
        .await
        .expect("failed to process ldap sync repl to scim");

    println!(
        "{}",
        serde_json::to_string_pretty(&scim_sync_request).unwrap()
    );

    assert!(scim_sync_request.from_state == expect_scim_request.from_state);

    assert!(scim_sync_request.to_state == expect_scim_request.to_state);

    assert!(scim_sync_request.entries == expect_scim_request.entries);

    assert!(scim_sync_request.delete_uuids == expect_scim_request.delete_uuids);
}

const TEST_LDAP_SYNC_REPL_1: &str = r#"
{
  "Success": {
    "cookie": "aXBhLXN5bmNyZXBsLWthbmkuZGV2LmJsYWNraGF0cy5uZXQuYXU6Mzg5I2NuPWRpcmVjdG9yeSBtYW5hZ2VyOmRjPWRldixkYz1ibGFja2hhdHMsZGM9bmV0LGRjPWF1Oih8KCYob2JqZWN0Q2xhc3M9cGVyc29uKShvYmplY3RDbGFzcz1pcGFudHVzZXJhdHRycykob2JqZWN0Q2xhc3M9cG9zaXhhY2NvdW50KSkoJihvYmplY3RDbGFzcz1ncm91cG9mbmFtZXMpKG9iamVjdENsYXNzPWlwYXVzZXJncm91cCkoIShvYmplY3RDbGFzcz1tZXBtYW5hZ2VkZW50cnkpKSkoJihvYmplY3RDbGFzcz1pcGF0b2tlbikob2JqZWN0Q2xhc3M9aXBhdG9rZW50b3RwKSkpIzEwOQ",
    "refresh_deletes": false,
    "entries": [
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
            "gidnumber": [
              "8200000"
            ],
            "homedirectory": [
              "/home/admin"
            ],
            "ipanthash": [
              "CVBguEizG80swI8sftaknw"
            ],
            "ipantsecurityidentifier": [
              "S-1-5-21-148961183-2750130983-218252910-500"
            ],
            "ipauniqueid": [
              "ad15f644-3498-11ed-95c3-5254006b0418"
            ],
            "krbextradata": [
              "AAL4hSJjcm9vdC9hZG1pbkBERVYuQkxBQ0tIQVRTLk5FVC5BVQA"
            ],
            "krblastadminunlock": [
              "20220915015504Z"
            ],
            "krblastfailedauth": [
              "20221108050316Z"
            ],
            "krblastpwdchange": [
              "20220915015504Z"
            ],
            "krbloginfailedcount": [
              "0"
            ],
            "krbpasswordexpiration": [
              "20221214015504Z"
            ],
            "krbprincipalkey": [
              "MIIB1KADAgEBoQMCAQGiAwIBAaMDAgEBpIIBvDCCAbgwdKAbMBmgAwIBBKESBBBgeEMvRkhoVWphRX0iKXxCoVUwU6ADAgEUoUwESiAAuyt8szEUVLiWVjSTuUgbgCf8heFMeIhSmGTgJpwL50kddprbdeKuOYvyxepdAil/MqHs4qdqj54reDDqFW0T2bg1Iv9O1cZEMGSgGzAZoAMCAQShEgQQU2xOXT16V21hPFkzPClsJKFFMEOgAwIBE6E8BDoQALfdG+243xBQDt01+bFr46DcZnlHctoSyUQKw8I8FzvRE1LK9Ttl5qkkOHADpA7XSj1lQ2RFqBsSMHSgGzAZoAMCAQShEgQQay9XSC9tPDJJVjIwUDxFRKFVMFOgAwIBEqFMBEogADJjxICRFFzpOcsxMY3xVedF3IBd7qzsQJlSvShaeKwyhTBFI/wvVDtQq6ogWKlACUcAVk2N6p91VtRHHjxXVhKQvT0kt/KS7zBkoBswGaADAgEEoRIEEE5nNTh5SmgpZic0bDAmNUWhRTBDoAMCARGhPAQ6EAClGqBf9jZWixZo/evVMVH01NkI1VpR0fNrGyvtML78p5j6TAne5Nms/wj9BtVawuv+h+Gz1fjdfw"
            ],
            "krbprincipalname": [
              "admin@DEV.BLACKHATS.NET.AU",
              "root@DEV.BLACKHATS.NET.AU"
            ],
            "loginshell": [
              "/bin/bash"
            ],
            "memberof": [
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
            "objectclass": [
              "inetuser",
              "ipantuserattrs",
              "ipaobject",
              "ipasshgroupofpubkeys",
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
            "uidnumber": [
              "8200000"
            ],
            "userpassword": [
              "{PBKDF2_SHA256}AAAIAJ3EnyWJXp/ytIk6sqf1BbLO9fzObD3q5I4y2bRFfgAFVo6CaRAaZ7KPYzU6Y340VSUV4NGRRcBjeU8q+aoTOkuzQM91jl+xlCydiB0CjeIDZ0tGy4NmQUFzfg7+exsKhNk2MfUrHcaqfZBtT7Lkfei4Rk7810TQf3NlHIRO8K3egPQ8Ox52Upw1E5QGEKQmDOjrtLtOF5gbyFtR5wc0wUJfmMhd/g65GkqFIr5vbPan3kL3ZqMhh1rrj4ISi9Ui8P7E8GDicoJDPwPf6YD9D0dx6yk72GyiuYt6p2aGJWMY897xqgB+YMgPptiDPik22ExoBAoHeJNIzKjITc2ohLLn6RkCk4GcCwMVZmcxesl/T/OMeSkNvoOM1zy7ANsGbQeaLqpViJSV0xT5PJ6NoIKMU2pIP57Q17VAlYigtCPU"
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
            "gidnumber": [
              "8200002"
            ],
            "ipantsecurityidentifier": [
              "S-1-5-21-148961183-2750130983-218252910-1002"
            ],
            "ipauniqueid": [
              "ad191e00-3498-11ed-b143-5254006b0418"
            ],
            "objectclass": [
              "groupofnames",
              "ipantgroupattrs",
              "ipaobject",
              "ipausergroup",
              "nestedgroup",
              "posixgroup",
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
            "ipauniqueid": [
              "0f233c48-3499-11ed-8e23-5254006b0418"
            ],
            "member": [
              "uid=admin,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
            ],
            "objectclass": [
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
        "entry_uuid": "babb8302-43a1-11ed-a50d-919b4b1a5ec0",
        "state": "Add",
        "entry": {
          "dn": "uid=testuser,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
          "attrs": {
            "cn": [
              "Test User"
            ],
            "displayname": [
              "Test User"
            ],
            "gecos": [
              "Test User"
            ],
            "gidnumber": [
              "12345"
            ],
            "givenname": [
              "Test"
            ],
            "homedirectory": [
              "/home/testuser"
            ],
            "initials": [
              "TU"
            ],
            "ipanthash": [
              "iEb36u6PsRetBr3YMLdYbA"
            ],
            "ipantsecurityidentifier": [
              "S-1-5-21-148961183-2750130983-218252910-1004"
            ],
            "ipauniqueid": [
              "d939d566-43a1-11ed-85aa-5254006b0418"
            ],
            "ipauserauthtype": [
              "password"
            ],
            "krbcanonicalname": [
              "testuser@DEV.BLACKHATS.NET.AU"
            ],
            "krbextradata": [
              "AAL732ljdGVzdHVzZXJAREVWLkJMQUNLSEFUUy5ORVQuQVUA"
            ],
            "krblastadminunlock": [
              "20221108044931Z"
            ],
            "krblastfailedauth": [
              "20221108045207Z"
            ],
            "krblastpwdchange": [
              "20221108045003Z"
            ],
            "krbloginfailedcount": [
              "0"
            ],
            "krbpasswordexpiration": [
              "20230206045003Z"
            ],
            "krbprincipalkey": [
              "MIIB1KADAgEBoQMCAQGiAwIBBKMDAgEBpIIBvDCCAbgwdKAbMBmgAwIBBKESBBAhIyRjVSl7LkVCXCZqISkkoVUwU6ADAgEUoUwESiAAyMSJYrMnu6mUnDV3ls7arH782SiSi1+vSFosLoLogJZQHKAxUljESwhySlEn+tAEF3yEenvuigNNDtFS/cYMn4oQ1c/vH4tnMGSgGzAZoAMCAQShEgQQOGVcI0Q7YS53OCdxcmd6WaFFMEOgAwIBE6E8BDoQAG6TZ38sFh9gXirZsZcZEiFls92uUh1+Azz7DxrCpo0B8+he39ACvuwLIaxzfswHZE8/pQUFRiHeMHSgGzAZoAMCAQShEgQQOFpvIFxvRlFEVilZVkYhRaFVMFOgAwIBEqFMBEogANBXnuehcaBtCPIXvaGcUEXXkGxiHlDIBFhXeu6l6w0Nj2Cm8Fezun8ip+si3JuxZkaK7TlxccZQOpjxSRuwekeKrzTNp+vS7jBkoBswGaADAgEEoRIEEFZDXFBrSEZDO0kuX2BORyihRTBDoAMCARGhPAQ6EAChj/DZFH3h9pW31ipzT4PrtdDcR83qla52bf+bLDV6LFV6FvFqq3fBJnpiIwuD9rPBBuDut+1ncg"
            ],
            "krbprincipalname": [
              "testuser@DEV.BLACKHATS.NET.AU"
            ],
            "loginshell": [
              "/bin/sh"
            ],
            "mail": [
              "testuser@dev.blackhats.net.au"
            ],
            "memberof": [
              "cn=ipausers,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
            ],
            "mepmanagedentry": [
              "cn=testuser,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
            ],
            "objectclass": [
              "inetorgperson",
              "inetuser",
              "ipantuserattrs",
              "ipaobject",
              "ipasshgroupofpubkeys",
              "ipasshuser",
              "ipauserauthtypeclass",
              "krbprincipalaux",
              "krbticketpolicyaux",
              "meporiginentry",
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
            "uidnumber": [
              "8200004"
            ],
            "userpassword": [
              "{PBKDF2_SHA256}AAAIAOTKJTaS7zR1u0ar5vDHPzcd9FoDiQVYvpT/n19NpTQJKJfdugke9vwpYxaZk+SnR/WHi4oeKd1IyaVmAC+H5d4qUYcc74xLGoyaezCNy8HkKBz9Q/9MD/gvzUjWUTYjbnXAMjzVpAHhVtzAoPrZVoWgXWkhga+YDsqKnqG0g1UeMTgja2zYr0mrG6Y+w+VJP3nnbQ9q4vpb7MGIs8xgjse+nIWZC+mPrK4ZEjSeE9Tjj+0C6nFq1+xU6KZK8NOG8kuHyVeS87zddJApqLSb2p6X/ixobak1j8VzXFd9lxewMfY+gieoXtn47KCFsquWGlavY4ZqjHYu4+MuHDTN/s8E06O/DkLLxPPO4iSH1B6pIaVTMHxsybX7FRLTj/MOb2+oYwWZty8WJ+dRD7gDg0vdUJr/H8EzJkrdXhNyz7f+"
            ]
          }
        }
      },
      {
        "entry_uuid": "f4dbef82-5f20-11ed-a50d-919b4b1a5ec0",
        "state": "Add",
        "entry": {
          "dn": "ipatokenuniqueid=380e27a4-438d-4c94-9dde-a3f6bc64ea1a,cn=otp,dc=dev,dc=blackhats,dc=net,dc=au",
          "attrs": {
            "ipatokenotpalgorithm": [
              "sha1"
            ],
            "ipatokenotpdigits": [
              "6"
            ],
            "ipatokenotpkey": [
              "hS/2a0DXBSKMJIlIcAJbBfCCZN0b8aTpoaJcj0RAAlV7QRQ"
            ],
            "ipatokenowner": [
              "uid=testuser,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
            ],
            "ipatokentotpclockoffset": [
              "0"
            ],
            "ipatokentotptimestep": [
              "30"
            ],
            "ipatokenuniqueid": [
              "380e27a4-438d-4c94-9dde-a3f6bc64ea1a"
            ],
            "objectclass": [
              "ipatoken",
              "ipatokentotp",
              "top"
            ]
          }
        }
      },
      {
        "entry_uuid": "d547c581-5f26-11ed-a50d-919b4b1a5ec0",
        "state": "Add",
        "entry": {
          "dn": "cn=testgroup,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
          "attrs": {
            "cn": [
              "testgroup"
            ],
            "description": [
              "Test group"
            ],
            "ipauniqueid": [
              "f1b96e6c-5f26-11ed-8cd2-5254006b0418"
            ],
            "objectclass": [
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
        "entry_uuid": "d547c583-5f26-11ed-a50d-919b4b1a5ec0",
        "state": "Add",
        "entry": {
          "dn": "cn=testexternal,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
          "attrs": {
            "cn": [
              "testexternal"
            ],
            "ipauniqueid": [
              "f67fd292-5f26-11ed-a6d0-5254006b0418"
            ],
            "objectclass": [
              "groupofnames",
              "ipaexternalgroup",
              "ipaobject",
              "ipausergroup",
              "nestedgroup",
              "top"
            ]
          }
        }
      },
      {
        "entry_uuid": "f90b0b81-5f26-11ed-a50d-919b4b1a5ec0",
        "state": "Add",
        "entry": {
          "dn": "cn=testposix,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
          "attrs": {
            "cn": [
              "testposix"
            ],
            "gidnumber": [
              "1234567"
            ],
            "ipauniqueid": [
              "fb64973e-5f26-11ed-9cfe-5254006b0418"
            ],
            "objectclass": [
              "groupofnames",
              "ipaobject",
              "ipausergroup",
              "nestedgroup",
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
}
"#;

const TEST_SCIM_SYNC_REPL_1: &str = r#"
{
  "from_state": "Refresh",
  "to_state": {
    "Active": {
      "cookie": "aXBhLXN5bmNyZXBsLWthbmkuZGV2LmJsYWNraGF0cy5uZXQuYXU6Mzg5I2NuPWRpcmVjdG9yeSBtYW5hZ2VyOmRjPWRldixkYz1ibGFja2hhdHMsZGM9bmV0LGRjPWF1Oih8KCYob2JqZWN0Q2xhc3M9cGVyc29uKShvYmplY3RDbGFzcz1pcGFudHVzZXJhdHRycykob2JqZWN0Q2xhc3M9cG9zaXhhY2NvdW50KSkoJihvYmplY3RDbGFzcz1ncm91cG9mbmFtZXMpKG9iamVjdENsYXNzPWlwYXVzZXJncm91cCkoIShvYmplY3RDbGFzcz1tZXBtYW5hZ2VkZW50cnkpKSkoJihvYmplY3RDbGFzcz1pcGF0b2tlbikob2JqZWN0Q2xhc3M9aXBhdG9rZW50b3RwKSkpIzEwOQ"
    }
  },
  "entries": [
    {
      "schemas": [
        "urn:ietf:params:scim:schemas:kanidm:1.0:sync:person"
      ],
      "id": "ac60034b-3498-11ed-a50d-919b4b1a5ec0",
      "externalId": "uid=admin,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
      "displayName": "Administrator",
      "gidNumber": 8200000,
      "homeDirectory": "/home/admin",
      "loginShell": "/bin/bash",
      "passwordImport": "ipaNTHash: CVBguEizG80swI8sftaknw",
      "userName": "admin"
    },
    {
      "schemas": [
        "urn:ietf:params:scim:schemas:kanidm:1.0:sync:group"
      ],
      "id": "ac60034e-3498-11ed-a50d-919b4b1a5ec0",
      "externalId": "cn=editors,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
      "description": "Limited admins who can edit other users",
      "gidNumber": 8200002,
      "name": "editors"
    },
    {
      "schemas": [
        "urn:ietf:params:scim:schemas:kanidm:1.0:sync:group"
      ],
      "id": "0c56a965-3499-11ed-a50d-919b4b1a5ec0",
      "externalId": "cn=trust admins,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
      "description": "Trusts administrators group",
      "members": [
        {
          "external_id": "uid=admin,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
        }
      ],
      "name": "trust admins"
    },
    {
      "schemas": [
        "urn:ietf:params:scim:schemas:kanidm:1.0:sync:person"
      ],
      "id": "babb8302-43a1-11ed-a50d-919b4b1a5ec0",
      "externalId": "uid=testuser,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
      "displayName": "Test User",
      "gidNumber": 12345,
      "homeDirectory": "/home/testuser",
      "loginShell": "/bin/sh",
      "passwordImport": "ipaNTHash: iEb36u6PsRetBr3YMLdYbA",
      "userName": "testuser"
    },
    {
      "schemas": [
        "urn:ietf:params:scim:schemas:kanidm:1.0:sync:group"
      ],
      "id": "d547c581-5f26-11ed-a50d-919b4b1a5ec0",
      "externalId": "cn=testgroup,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
      "description": "Test group",
      "name": "testgroup"
    },
    {
      "schemas": [
        "urn:ietf:params:scim:schemas:kanidm:1.0:sync:group"
      ],
      "id": "d547c583-5f26-11ed-a50d-919b4b1a5ec0",
      "externalId": "cn=testexternal,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
      "name": "testexternal"
    },
    {
      "schemas": [
        "urn:ietf:params:scim:schemas:kanidm:1.0:sync:group"
      ],
      "id": "f90b0b81-5f26-11ed-a50d-919b4b1a5ec0",
      "externalId": "cn=testposix,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
      "gidNumber": 1234567,
      "name": "testposix"
    }
  ],
  "delete_uuids": []
}
"#;

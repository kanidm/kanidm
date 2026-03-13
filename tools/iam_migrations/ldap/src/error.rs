#[derive(Clone, Debug)]
pub enum SyncError {
    ClientConfig,
    TlsInvalidCertificate,
    TlsInvalidCaStore,
    LdapConn,
    LdapAuth,
    LdapSyncrepl,
    LdapStateInvalid,
    SyncStatus,
    SyncUpdate,
    Preprocess,
}

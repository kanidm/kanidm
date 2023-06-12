#[derive(Clone, Debug)]
pub enum SyncError {
    ClientConfig,
    LdapConn,
    LdapAuth,
    LdapSyncrepl,
    LdapStateInvalid,
    SyncStatus,
    SyncUpdate,
    Preprocess,
}

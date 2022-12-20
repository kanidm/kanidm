#[derive(Clone, Debug)]
pub enum SyncError {
    ClientConfig,
    LdapConn,
    LdapAuth,
    LdapSyncrepl,
    SyncStatus,
    SyncUpdate,
    Preprocess,
}

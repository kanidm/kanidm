use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use core::pin::Pin;
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use openssl::ssl::{Ssl, SslConnector, SslMethod, SslVerifyMode};
// use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_openssl::SslStream;
use tokio_util::codec::Framed;

use ldap3_server::proto::*;
use ldap3_server::LdapCodec;

struct LdapInner {
    pub framed: Framed<SslStream<TcpStream>, LdapCodec>,
    pub msgid: i32,
}

pub enum LdapSchema {
    Kanidm,
    Rfc2307bis,
}

pub struct LdapClient {
    pub uri: String,
    pub addr: SocketAddr,
    pub basedn: String,
    pub schema: LdapSchema,
    conn: Mutex<Option<LdapInner>>,
}

impl std::fmt::Debug for LdapClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapClient")
            .field("uri", &self.uri)
            .field("addr", &self.addr)
            .finish()
    }
}

impl LdapClient {
    pub fn new(uri: String, basedn: String, schema: LdapSchema) -> Result<Self, ()> {
        // Turn this into an address.
        debug!("ldap_uri {}", uri);

        // First remove the ldaps from the start.
        let trimmed = uri.trim_start_matches("ldaps://");

        // Then provide the rest to the to_socket_addrs.
        let addr = match trimmed.to_socket_addrs() {
            Ok(mut addrs_iter) => match addrs_iter.next() {
                Some(addr) => addr,
                None => {
                    error!("No ldap uri addresses found");
                    return Err(());
                }
            },
            Err(e) => {
                error!("Unable to parse LDAP uri address - {:?}", e);
                return Err(());
            }
        };

        debug!("addr -> {:?}", addr);

        // now we store this for the tcp stream later.
        // https://docs.rs/tokio/1.5.0/tokio/net/struct.TcpStream.html

        Ok(LdapClient {
            uri,
            addr,
            basedn,
            schema,
            conn: Mutex::new(None),
        })
    }

    async fn bind(&self, dn: String, pw: String) -> Result<(), ()> {
        let msg = LdapMsg {
            msgid: 1,
            op: LdapOp::BindRequest(LdapBindRequest {
                dn,
                cred: LdapBindCred::Simple(pw),
            }),
            ctrl: vec![],
        };

        let tcpstream = TcpStream::connect(self.addr)
            .await
            .map_err(|e| error!("Failed to connect to {} -> {:?}", self.uri, e))?;

        // Now add TLS
        let mut tls_parms = SslConnector::builder(SslMethod::tls_client()).map_err(|e| {
            error!("openssl -> {:?}", e);
        })?;
        tls_parms.set_verify(SslVerifyMode::NONE);
        let tls_parms = tls_parms.build();

        let mut tlsstream = Ssl::new(tls_parms.context())
            .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
            .map_err(|e| {
                error!("Failed to initialise TLS -> {:?}", e);
            })?;

        let _ = SslStream::connect(Pin::new(&mut tlsstream))
            .await
            .map_err(|e| {
                error!("Failed to initialise TLS -> {:?}", e);
            })?;

        let mut framed = Framed::new(tlsstream, LdapCodec);

        let _ = framed.send(msg).await.map_err(|e| {
            error!("Unable to bind -> {:?}", e);
        })?;

        if let Some(Ok(msg)) = framed.next().await {
            if let LdapOp::BindResponse(res) = msg.op {
                if res.res.code == LdapResultCode::Success {
                    let mut mguard = self.conn.lock().await;
                    *mguard = Some(LdapInner { framed, msgid: 1 });

                    return Ok(());
                }
            }
        }
        error!("Failed to bind");
        Err(())
    }

    pub async fn open_dm_connection(&self, pw: &str) -> Result<(), ()> {
        self.bind("cn=Directory Manager".to_string(), pw.to_string())
            .await
    }

    pub async fn open_user_connection(
        &self,
        test_start: Instant,
        name: &str,
        pw: &str,
    ) -> Result<(Duration, Duration), ()> {
        let dn = match self.schema {
            LdapSchema::Kanidm => name.to_string(),
            LdapSchema::Rfc2307bis => format!("uid={},ou=people,{}", name, self.basedn),
        };

        let start = Instant::now();

        self.bind(dn, pw.to_string()).await?;

        let end = Instant::now();
        let diff = end.duration_since(start);
        let rel_diff = start.duration_since(test_start);

        Ok((rel_diff, diff))
    }

    pub async fn close_connection(&self) {
        let mut mguard = self.conn.lock().await;
        *mguard = None;
    }

    pub async fn search_name(
        &self,
        test_start: Instant,
        ids: &[String],
    ) -> Result<(Duration, Duration, usize), ()> {
        let name_attr = match self.schema {
            LdapSchema::Kanidm => "name",
            LdapSchema::Rfc2307bis => "cn",
        };

        let filter = LdapFilter::Or(
            ids.iter()
                .map(|n| LdapFilter::Equality(name_attr.to_string(), n.to_string()))
                .collect(),
        );

        let start = Instant::now();

        let res = self.search(filter).await?;

        let end = Instant::now();
        let diff = end.duration_since(start);
        let rel_diff = start.duration_since(test_start);

        Ok((rel_diff, diff, res.len()))
    }

    pub async fn search(&self, filter: LdapFilter) -> Result<Vec<LdapSearchResultEntry>, ()> {
        // Create the search filter
        let req = LdapSearchRequest {
            base: self.basedn.clone(),
            scope: LdapSearchScope::Subtree,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter,
            attrs: vec![],
        };

        // Prep the proto msg
        let mut mguard = self.conn.lock().await;
        let inner = match (*mguard).as_mut() {
            Some(i) => i,
            None => {
                error!("No connection available");
                return Err(());
            }
        };

        inner.msgid += 1;
        let msgid = inner.msgid;

        let msg = LdapMsg {
            msgid,
            ctrl: vec![],
            op: LdapOp::SearchRequest(req),
        };

        // Send it
        let _ = inner.framed.send(msg).await.map_err(|e| {
            error!("Unable to search -> {:?}", e);
        })?;

        let mut results = Vec::new();
        // It takes a lot more work to process a response from ldap :(
        while let Some(Ok(msg)) = inner.framed.next().await {
            match msg.op {
                LdapOp::SearchResultEntry(ent) => results.push(ent),
                LdapOp::SearchResultDone(res) => {
                    if res.code == LdapResultCode::Success {
                        break;
                    } else {
                        error!("Search Failed -> {:?}", res);
                        return Err(());
                    }
                }
                _ => {
                    error!("Invalid ldap response state");
                    return Err(());
                }
            }
        }
        Ok(results)
    }

    pub async fn delete(&self, dn: String) -> Result<(), ()> {
        let mut mguard = self.conn.lock().await;
        let inner = match (*mguard).as_mut() {
            Some(i) => i,
            None => {
                error!("No connection available");
                return Err(());
            }
        };

        inner.msgid += 1;
        let msgid = inner.msgid;

        let msg = LdapMsg {
            msgid,
            ctrl: vec![],
            op: LdapOp::DelRequest(dn),
        };

        // Send it
        let _ = inner.framed.send(msg).await.map_err(|e| {
            error!("Unable to delete -> {:?}", e);
        })?;
        if let Some(Ok(msg)) = inner.framed.next().await {
            if let LdapOp::DelResponse(res) = msg.op {
                if res.code == LdapResultCode::Success {
                    return Ok(());
                } else {
                    error!("Delete Failed -> {:?}", res);
                    return Err(());
                }
            }
        }
        error!("Invalid ldap response state");
        Err(())
    }

    pub async fn add(&self, req: LdapAddRequest) -> Result<(), ()> {
        let mut mguard = self.conn.lock().await;
        let inner = match (*mguard).as_mut() {
            Some(i) => i,
            None => {
                error!("No connection available");
                return Err(());
            }
        };

        inner.msgid += 1;
        let msgid = inner.msgid;

        let msg = LdapMsg {
            msgid,
            ctrl: vec![],
            op: LdapOp::AddRequest(req),
        };

        // Send it
        let _ = inner.framed.send(msg).await.map_err(|e| {
            error!("Unable to add -> {:?}", e);
        })?;
        if let Some(Ok(msg)) = inner.framed.next().await {
            if let LdapOp::AddResponse(res) = msg.op {
                if res.code == LdapResultCode::Success {
                    return Ok(());
                } else {
                    error!("Add Failed -> {:?}", res);
                    return Err(());
                }
            }
        }
        error!("Invalid ldap response state");
        Err(())
    }

    pub async fn modify(&self, req: LdapModifyRequest) -> Result<(), ()> {
        let mut mguard = self.conn.lock().await;
        let inner = match (*mguard).as_mut() {
            Some(i) => i,
            None => {
                error!("No connection available");
                return Err(());
            }
        };

        inner.msgid += 1;
        let msgid = inner.msgid;

        let msg = LdapMsg {
            msgid,
            ctrl: vec![],
            op: LdapOp::ModifyRequest(req),
        };

        // Send it
        let _ = inner.framed.send(msg).await.map_err(|e| {
            error!("Unable to modify -> {:?}", e);
        })?;
        if let Some(Ok(msg)) = inner.framed.next().await {
            if let LdapOp::ModifyResponse(res) = msg.op {
                if res.code == LdapResultCode::Success {
                    return Ok(());
                } else {
                    error!("Modify Failed -> {:?}", res);
                    return Err(());
                }
            }
        }
        error!("Invalid ldap response state");
        Err(())
    }
}

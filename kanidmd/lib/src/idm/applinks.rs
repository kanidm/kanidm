use crate::idm::server::IdmServerProxyReadTransaction;
use crate::prelude::*;
use kanidm_proto::internal::AppLink;

impl<'a> IdmServerProxyReadTransaction<'a> {
    pub fn list_applinks(&self, ident: &Identity) -> Result<Vec<AppLink>, OperationError> {
        // From the member-of of the ident.
        let ident_mo = match ident.get_memberof() {
            Some(mo) => mo,
            None => {
                debug!("Ident has no memberof, no applinks are present");
                return Ok(Vec::with_capacity(0));
            }
        };

        // Do an internal search
        // ⚠️  Safety Notes - We perform an internal search here which bypasses
        // access controls. Why? Users normally can't read the oauth2_rs_scope_maps
        // since that could (?) disclose access rules. It's probably not a risk, but
        // we just don't show them by default.
        //
        // This IS safe because we control *all* inputs (the uuids and memberof) and
        // they come from the cryptographically verified UAT. we also control all
        // outputs and ONLY output data that IS visible by default for an oauth2
        // resource server.
        //
        // This is kind of a limitation of the kani search system, where the ability to
        // compare an attribute, also allows you to read it. In this case we want compare
        // without read, but it's not really possible, and it's a silly concept generally
        // anyway because publicly allowing that allows retrieval of the values to bruteforce.
        let f = filter!(f_or(
            ident_mo
                .iter()
                .copied()
                .map(|uuid| { f_eq("oauth2_rs_scope_map", PartialValue::Refer(uuid)) })
                .collect()
        ));

        let oauth2_related = self.qs_read.internal_search(f)?;
        trace!(?oauth2_related);

        // Aggregate results to a Vec of AppLink
        let apps = oauth2_related
            .iter()
            .filter_map(|entry| {
                let display_name = entry
                    .get_ava_single_utf8("displayname")
                    .map(str::to_string)?;

                let redirect_url = entry
                    .get_ava_single_url("oauth2_rs_origin_landing")
                    .or_else(|| entry.get_ava_single_url("oauth2_rs_origin"))
                    .cloned()?;

                let name = entry
                    .get_ava_single_iname("oauth2_rs_name")
                    .map(str::to_string)?;

                Some(AppLink::Oauth2 {
                    name,
                    display_name,
                    redirect_url,
                    icon: None,
                })
            })
            .collect::<Vec<_>>();

        debug!("returned {} related apps", apps.len());
        trace!(?apps);

        Ok(apps)
    }
}

#[cfg(test)]
mod tests {
    // use crate::prelude::*;
    use crate::event::{CreateEvent, ModifyEvent};
    use async_std::task;
    use kanidm_proto::internal::AppLink;

    #[test]
    fn test_idm_applinks_list() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = duration_from_epoch_now();
            let mut idms_prox_write = task::block_on(idms.proxy_write(ct.clone()));

            // Create an RS, the user and a group..
            let usr_uuid = Uuid::new_v4();
            let grp_uuid = Uuid::new_v4();

            let e_rs: Entry<EntryInit, EntryNew> = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("oauth2_resource_server")),
                ("class", Value::new_class("oauth2_resource_server_basic")),
                ("oauth2_rs_name", Value::new_iname("test_resource_server")),
                ("displayname", Value::new_utf8s("test_resource_server")),
                (
                    "oauth2_rs_origin",
                    Value::new_url_s("https://demo.example.com").unwrap()
                ),
                (
                    "oauth2_rs_origin_landing",
                    Value::new_url_s("https://demo.example.com/landing").unwrap()
                ),
                // System admins
                (
                    "oauth2_rs_scope_map",
                    Value::new_oauthscopemap(grp_uuid, btreeset!["read".to_string()])
                        .expect("invalid oauthscope")
                )
            );

            let e_usr = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("account")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testaccount")),
                ("uuid", Value::Uuid(usr_uuid)),
                ("description", Value::new_utf8s("testaccount")),
                ("displayname", Value::new_utf8s("Test Account"))
            );

            let e_grp = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("group")),
                ("uuid", Value::Uuid(grp_uuid)),
                ("name", Value::new_iname("test_oauth2_group"))
            );

            let ce = CreateEvent::new_internal(vec![e_rs, e_grp, e_usr]);
            assert!(idms_prox_write.qs_write.create(&ce).is_ok());
            assert!(idms_prox_write.commit().is_ok());

            // Now do an applink query, they will not be there.
            let idms_prox_read = task::block_on(idms.proxy_read());

            let ident = idms_prox_read
                .qs_read
                .internal_search_uuid(usr_uuid)
                .map(Identity::from_impersonate_entry_readonly)
                .expect("Failed to impersonate identity");

            let apps = idms_prox_read
                .list_applinks(&ident)
                .expect("Failed to access related apps");

            assert!(apps.is_empty());
            drop(idms_prox_read);

            // Add them to the group.
            let mut idms_prox_write = task::block_on(idms.proxy_write(ct.clone()));
            let me_inv_m = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("uuid", PartialValue::Refer(grp_uuid))),
                    ModifyList::new_append("member", Value::Refer(usr_uuid)),
                )
            };
            assert!(idms_prox_write.qs_write.modify(&me_inv_m).is_ok());
            assert!(idms_prox_write.commit().is_ok());

            let idms_prox_read = task::block_on(idms.proxy_read());

            let ident = idms_prox_read
                .qs_read
                .internal_search_uuid(usr_uuid)
                .map(Identity::from_impersonate_entry_readonly)
                .expect("Failed to impersonate identity");

            let apps = idms_prox_read
                .list_applinks(&ident)
                .expect("Failed to access related apps");

            let app = apps.get(0).expect("No apps return!");

            assert!(match app {
                AppLink::Oauth2 {
                    name,
                    display_name,
                    redirect_url,
                    icon,
                } => {
                    name == "test_resource_server"
                        && display_name == "test_resource_server"
                        && redirect_url == &Url::parse("https://demo.example.com/landing").unwrap()
                        && icon.is_none()
                } // _ => false,
            })
        })
    }
}

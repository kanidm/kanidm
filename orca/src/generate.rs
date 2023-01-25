use std::fs::File;
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

use std::collections::{HashMap, HashSet};

use crate::data::*;

const N_USERS: usize = 3000;
const N_GROUPS: usize = 1500;
const N_MEMBERSHIPS: usize = 10;
const N_NEST: usize = 4;

pub(crate) fn doit(output: &Path) {
    info!(
        "Performing data generation into {}",
        output.to_str().unwrap(),
    );

    let mut rng = rand::thread_rng();

    if N_MEMBERSHIPS >= N_GROUPS {
        error!("Too many memberships per group. Memberships must be less that n-groups");
        return;
    }

    // Open before we start so we have it ready to go.
    let out_file = match File::create(output) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open {} - {:?}", output.to_str().unwrap(), e);
            return;
        }
    };

    // Number of users
    let accounts: Vec<_> = (0..N_USERS)
        .map(|i| Account {
            name: format!("testuser{}", i),
            display_name: format!("Test User {}", i),
            password: readable_password_from_random(),
            uuid: Uuid::new_v4(),
        })
        .collect();

    // Number of groups.
    let mut groups: Vec<_> = (0..N_GROUPS)
        .map(|i| Group {
            name: format!("testgroup{}", i),
            uuid: Uuid::new_v4(),
            members: Vec::new(),
        })
        .collect();

    // Should groups be randomly nested?
    // The way this is done is we split the array based on nest level. If it's 1, we split
    // in 2, 2 we split in 3 and so on.
    if N_NEST > 0 {
        debug!("Nesting Groups");

        let chunk_size = N_GROUPS / (N_NEST + 1);
        if chunk_size == 0 {
            error!("Unable to chunk groups, need (N_GROUPS / (N_NEST + 1)) > 0");
            return;
        }

        let mut chunk_iter = groups.chunks_mut(chunk_size);
        // Can't fail due to above checks.
        let mut p_chunk = chunk_iter.next().unwrap();
        // while let Some(w_chunk) = chunk_iter.next() {
        for w_chunk in chunk_iter {
            // add items from work chunk to parent chunk
            p_chunk
                .iter_mut()
                .zip(w_chunk.iter())
                .for_each(|(p, w): (&mut _, &_)| p.members.push(w.uuid));

            // swap w_chunk to p_chunk
            p_chunk = w_chunk;
        }
    }

    // Number of memberships per user.
    // We use rand for this to sample random numbers of
    for acc in accounts.iter() {
        // Sample randomly.
        for idx in rand::seq::index::sample(&mut rng, N_GROUPS, N_MEMBERSHIPS).iter() {
            groups[idx].members.push(acc.uuid);
        }
    }

    // Build from the generated data above.
    let all_entities: HashMap<Uuid, Entity> = accounts
        .into_iter()
        .map(|acc| (acc.uuid, Entity::Account(acc)))
        .chain(groups.into_iter().map(|grp| (grp.uuid, Entity::Group(grp))))
        .collect();

    // Define the entries that should exist "at the start of the test". For now, we just
    // create everything. Maybe when we start to add mod tests we need to retain a pool
    // of things to retain here for those ops.
    let precreate: HashSet<_> = all_entities.keys().copied().collect();

    // The set of accounts in all_entities.
    let accounts: HashSet<Uuid> = all_entities
        .iter()
        .filter_map(|(uuid, ent)| match ent {
            Entity::Account(_) => Some(*uuid),
            _ => None,
        })
        .collect();

    // This defines a map of "entity" to "what can it manipulate". This
    // is used to create access controls in some cases for mod tests.
    //
    // For example, if we have user with uuid X and it changes Group with
    // uuid Y, then we need to ensure that X has group-mod permissions over
    // Y in some capacity.
    let access: HashMap<Uuid, Vec<EntityType>> = HashMap::new();

    // The set of operations to simulate. We pre-calc these so tests can randomly
    // sample and perform the searches as needed.

    // We don't have original times, so we can fudge these.
    let orig_etime = Duration::from_secs(1);
    let rtime = Duration::from_secs(1);
    // Needed for random sampling.
    let all_ids: Vec<_> = all_entities.keys().copied().collect();
    let all_ids_len = all_ids.len();

    let connections: Vec<_> = (0..all_ids_len)
        .map(|id| {
            // Could be rand?
            let n_search = 1;

            let mut search_ids = Vec::new();
            for idx in rand::seq::index::sample(&mut rng, all_ids_len, n_search).iter() {
                search_ids.push(all_ids[idx]);
            }
            //
            Conn {
                id: id as i32,
                ops: vec![Op {
                    orig_etime,
                    rtime,
                    op_type: OpType::Search(search_ids),
                }],
            }
        })
        .collect();

    let td = TestData {
        all_entities,
        access,
        accounts,
        precreate,
        connections,
    };

    if let Err(e) = serde_json::to_writer_pretty(out_file, &td) {
        error!("Writing to file -> {:?}", e);
    };
}

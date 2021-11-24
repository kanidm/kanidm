use crate::data::*;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryFrom;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct RawRecord {
    conn: String,
    etime: String,
    ids: Vec<Uuid>,
    nentries: u32,
    rtime: String,
    #[serde(rename = "type")]
    op_type: String,
}

#[derive(Debug, PartialEq)]
enum RawOpType {
    Precreate,
    Add,
    Search,
    Mod,
    Delete,
    Bind,
}

impl FromStr for RawOpType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "precreate" => Ok(RawOpType::Precreate),
            "srch" => Ok(RawOpType::Search),
            "bind" => Ok(RawOpType::Bind),
            "mod" => Ok(RawOpType::Mod),
            "del" => Ok(RawOpType::Delete),
            "add" => Ok(RawOpType::Add),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
struct Record {
    conn: i32,
    etime: Duration,
    ids: Vec<Uuid>,
    _nentries: u32,
    rtime: Duration,
    op_type: RawOpType,
}

fn parse_rtime(s: &str) -> Result<Duration, ()> {
    // R times are "0:00:00" or "1:34:51.714690"
    // So we need to split on :, and then parse each part.
    // This is HH:MM:SS.ms
    let v: Vec<&str> = s.split(':').collect();

    if v.len() != 3 {
        return Err(());
    }

    let hh = v[0].parse::<u32>().map_err(|_| ())?;
    let mm = v[1].parse::<u32>().map_err(|_| ())?;
    let ss = f64::from_str(v[2]).map_err(|_| ())?;

    let ext_secs = ((mm * 60) + (hh * 3600)) as f64;

    Ok(Duration::from_secs_f64(ext_secs + ss))
}

impl Record {
    #[allow(clippy::wrong_self_convention)]
    fn into_op(&self, all_entities: &HashMap<Uuid, Entity>, exists: &mut Vec<Uuid>) -> Op {
        let op_type = match self.op_type {
            RawOpType::Add => {
                self.ids.iter().for_each(|id| {
                    if let Err(idx) = exists.binary_search(id) {
                        exists.insert(idx, *id);
                    } else {
                        panic!();
                    }
                });
                // Map them all

                let new = self
                    .ids
                    .iter()
                    .map(|id| all_entities.get(id).unwrap().get_uuid())
                    .collect();

                OpType::Add(new)
            }
            RawOpType::Search => OpType::Search(self.ids.clone()),
            RawOpType::Mod => {
                let mut rng = &mut rand::thread_rng();
                let max_m = (exists.len() / 3) + 1;
                let mods = self
                    .ids
                    .iter()
                    .map(|id| {
                        match all_entities.get(id) {
                            Some(Entity::Account(_a)) => (*id, Change::Account),
                            Some(Entity::Group(_g)) => {
                                // This could be better! It's quite an evil method at the moment...
                                let m = rng.gen_range(0..max_m);
                                let ngrp = exists.choose_multiple(&mut rng, m).cloned().collect();
                                (*id, Change::Group(ngrp))
                            }
                            None => {
                                panic!();
                            }
                        }
                    })
                    .collect();
                OpType::Mod(mods)
            }
            RawOpType::Delete => {
                // Remove them.
                self.ids.iter().for_each(|id| {
                    if let Ok(idx) = exists.binary_search(id) {
                        exists.remove(idx);
                    } else {
                        panic!();
                    }
                });
                // Could consider checking that everything DOES exist before we start ...
                OpType::Delete(self.ids.clone())
            }
            RawOpType::Bind => OpType::Bind(self.ids[0]),
            _ => panic!(),
        };
        Op {
            orig_etime: self.etime,
            rtime: self.rtime,
            op_type,
        }
    }
}

impl TryFrom<RawRecord> for Record {
    type Error = ();

    fn try_from(value: RawRecord) -> Result<Self, Self::Error> {
        let RawRecord {
            conn,
            etime,
            mut ids,
            nentries,
            rtime,
            op_type,
        } = value;

        let conn = conn.parse::<i32>().map_err(|_| ())?;
        let etime = f64::from_str(&etime)
            .map(Duration::from_secs_f64)
            .map_err(|_| ())?;

        let op_type = RawOpType::from_str(&op_type).map_err(|_| ())?;

        let rtime = parse_rtime(&rtime).map_err(|_| ())?;

        ids.sort_unstable();
        ids.dedup();

        Ok(Record {
            conn,
            etime,
            ids,
            _nentries: nentries,
            rtime,
            op_type,
        })
    }
}

pub fn doit(input: &Path, output: &Path) {
    info!(
        "Preprocessing data from {} to {} ...",
        input.to_str().unwrap(),
        output.to_str().unwrap()
    );

    let file = match File::open(input) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open {} - {:?}", input.to_str().unwrap(), e);
            return;
        }
    };

    let out_file = match File::create(output) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open {} - {:?}", output.to_str().unwrap(), e);
            return;
        }
    };

    let reader = BufReader::new(file);

    let u: Vec<RawRecord> = match serde_json::from_reader(reader) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to parse {} - {:?}", input.to_str().unwrap(), e);
            return;
        }
    };

    let data: Result<Vec<_>, _> = u.into_iter().map(Record::try_from).collect();

    let data = match data {
        Ok(d) => d,
        Err(_) => {
            error!("Failed to transform record");
            return;
        }
    };

    // Now we can start to preprocess everything.
    let mut rng = &mut rand::thread_rng();

    // We need to know all id's of entries that will ever exist
    let all_ids: HashSet<Uuid> = data
        .iter()
        .flat_map(|rec| rec.ids.iter())
        .copied()
        .collect();

    // Remove anything that is a pre-create event.
    let (precreate, mut other): (Vec<_>, Vec<_>) = data
        .into_iter()
        .partition(|rec| rec.op_type == RawOpType::Precreate);

    // Before we can precreate, we need an idea to what each
    // item is. Lets get all ids and see which ones ever did a bind.
    // This means they are probably an account.
    let accounts: HashSet<Uuid> = other
        .iter()
        .filter(|rec| rec.op_type == RawOpType::Bind)
        .flat_map(|rec| rec.ids.iter())
        .copied()
        .collect();

    let mut precreate: Vec<Uuid> = precreate
        .iter()
        .flat_map(|rec| rec.ids.iter())
        .copied()
        .collect();

    precreate.sort_unstable();
    precreate.dedup();

    let max_m = (all_ids.len() / 3) + 1;

    // Now generate what our db entities all look like in one pass. This is a combo
    // of the precreate ids, and the ids that are ever accessed.

    let all_entities: HashMap<Uuid, Entity> = all_ids
        .iter()
        .map(|id| {
            let ent = if accounts.contains(id) {
                Entity::Account(Account::generate(*id))
            } else {
                // Choose the number of members:
                let m = rng.gen_range(0..max_m);
                let members = (&precreate).choose_multiple(&mut rng, m).cloned().collect();
                Entity::Group(Group::generate(*id, members))
            };
            (*id, ent)
        })
        .collect();

    // Order everything, this will make it easier to get everything into connection groups
    // with their sub-operations in a correct order.
    other.sort_by(|a, b| match a.conn.cmp(&b.conn) {
        Ordering::Equal => a.rtime.cmp(&b.rtime),
        r => r,
    });

    let mut connections: BTreeMap<i32, Conn> = BTreeMap::new();

    let mut exists = precreate.clone();

    // Consume all the remaining records into connection structures.
    other.iter().for_each(|rec| {
        debug!("{:?}", rec);
        if let Some(c) = connections.get_mut(&rec.conn) {
            c.ops.push(rec.into_op(&all_entities, &mut exists));
        } else {
            connections.insert(
                rec.conn,
                Conn {
                    id: rec.conn,
                    ops: vec![rec.into_op(&all_entities, &mut exists)],
                },
            );
        }
    });

    // now collect these into the set of connections containing their operations.
    let connections: Vec<_> = connections.into_iter().map(|(_, v)| v).collect();

    // Now from the set of connections, we need to know what access may or may not
    // be required.
    let mut access: HashMap<Uuid, Vec<EntityType>> = HashMap::new();

    connections.iter().for_each(|conn| {
        let mut curbind = None;
        // start by assuming there is no auth
        conn.ops.iter().for_each(|op| {
            // if it's a bind, update our current access.
            match &op.op_type {
                OpType::Bind(id) => curbind = Some(id),
                OpType::Add(list) | OpType::Delete(list) => {
                    if let Some(id) = curbind.as_ref() {
                        let mut nlist: Vec<EntityType> = list
                            .iter()
                            .map(|uuid| all_entities.get(uuid).unwrap().get_entity_type())
                            .collect();

                        if let Some(ac) = access.get_mut(id) {
                            ac.append(&mut nlist);
                        } else {
                            access.insert(**id, nlist);
                        }
                    } else {
                        // Else, no current bind, wtf?
                        panic!();
                    }
                }
                OpType::Mod(list) => {
                    if let Some(id) = curbind.as_ref() {
                        let mut nlist: Vec<EntityType> = list
                            .iter()
                            .map(|v| all_entities.get(&v.0).unwrap().get_entity_type())
                            .collect();

                        if let Some(ac) = access.get_mut(id) {
                            ac.append(&mut nlist);
                        } else {
                            access.insert(**id, nlist);
                        }
                    } else {
                        // Else, no current bind, wtf?
                        panic!();
                    }
                }
                OpType::Search(_) => {}
            }
            // if it's a mod, declare we need that.
        });
    });

    // For each access
    // sort/dedup them.
    access.values_mut().for_each(|v| {
        v.sort_unstable();
        v.dedup();
    });

    let precreate: HashSet<_> = precreate.into_iter().collect();

    // Create the struct
    let td = TestData {
        all_entities,
        access,
        accounts,
        precreate,
        connections,
    };

    // Finally, write it out;
    if let Err(e) = serde_json::to_writer_pretty(out_file, &td) {
        error!("Writing to file -> {:?}", e);
    };
}

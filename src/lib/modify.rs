use proto_v1::ModifyList as ProtoModifyList;
use proto_v1::Modify as ProtoModify;

#[derive(Serialize, Deserialize, Debug)]
pub enum Modify {
    // This value *should* exist.
    Present(String, String),
    // This value *should not* exist.
    Removed(String, String),
    // This attr *should not* exist.
    Purged(String),
}

impl Modify {
    pub fn from(m: &ProtoModify) -> Self {
        match m {
            ProtoModify::Present(a, v) => {
                Modify::Present(a.clone(), v.clone())
            }
            ProtoModify::Removed(a, v) => {
                Modify::Removed(a.clone(), v.clone())
            }
            ProtoModify::Purged(a) => {
                Modify::Purged(a.clone())
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ModifyList {
    // And ordered list of changes to apply. Should this be state based?
    pub mods: Vec<Modify>,
}

impl ModifyList {
    pub fn new() -> Self {
        ModifyList { mods: Vec::new() }
    }

    pub fn new_list(mods: Vec<Modify>) -> Self {
        ModifyList { mods: mods }
    }

    pub fn push_mod(&mut self, modify: Modify) {
        self.mods.push(modify)
    }

    pub fn len(&self) -> usize {
        self.mods.len()
    }

    pub fn from(ml: &ProtoModifyList) -> Self {
        // For each ProtoModify, do a from.

        ModifyList {
            mods: ml.mods.iter()
                .map(|pm| {
                    Modify::from(pm)
                })
                .collect()
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Modify {
    // This value *should* exist.
    Present(String, String),
    // This value *should not* exist.
    Removed(String, String),
    // This attr *should not* exist.
    Purged(String),
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
}

use uuid::Uuid;

pub trait KeyObject {
    fn uuid(&self) -> Uuid;

    // Provider?
}

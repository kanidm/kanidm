pub mod v1;

pub enum AuthPkgRequest {
	V1(v1::enums::AuthPkgRequestV1),
}

pub enum AuthPkgResponse {
	V1(v1::enums::AuthPkgResponseV1),
}

pub mod v1;

pub enum AuthPkgRequest {
	V1(v1::AuthPkgRequestV1),
}

pub enum AuthPkgResponse {
	V1(v1::AuthPkgResponseV1),
}

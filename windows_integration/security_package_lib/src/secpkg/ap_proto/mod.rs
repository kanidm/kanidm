pub mod v1;

pub enum AuthPkgRequest {
	V1(v1::AuthPkgRequest),
}

pub enum AuthPkgResponse {
	V1(v1::AuthPkgResponse),
}

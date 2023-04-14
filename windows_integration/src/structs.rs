use kanidm_proto::v1::UnixUserToken;
use windows::Win32::Foundation::UNICODE_STRING;

pub struct AuthInfo {
	pub username: UNICODE_STRING,
	pub password: UNICODE_STRING,
}

pub struct ProfileBuffer {
	pub token: UnixUserToken,
}
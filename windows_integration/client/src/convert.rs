use tracing::{event, Level};
use windows::{Win32::Foundation::UNICODE_STRING, core::PWSTR};

pub fn unicode_to_rust(string: UNICODE_STRING) -> Option<String> {
	return match unsafe { string.Buffer.to_string() } {
		Ok(string) => Some(string),
		Err(_) => {
			event!(Level::WARN, "Failed to convert windows unicode string to rust string");
			None
		}
	}
}

pub fn rust_to_unicode(string: String) -> UNICODE_STRING {
	let mut utf16: Vec<u16> = string.encode_utf16().collect();
	utf16.push(0); // Null terminator

	let buffer = PWSTR(utf16.as_mut_ptr());
	let length = (utf16.len() - 1) as u16;
	let maximum_length = utf16.len() as u16;

	// https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
	UNICODE_STRING {
		Buffer: buffer,
		Length: length,
		MaximumLength: maximum_length,
	}
}


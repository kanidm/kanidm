use std::{mem, ffi::c_void, ptr::null_mut};

use windows::Win32::{Security::Authentication::Identity::{PLSA_ALLOCATE_LSA_HEAP, PLSA_ALLOCATE_CLIENT_BUFFER}, Foundation::STATUS_SUCCESS};

pub enum MemoryAllocationError {
	NoAllocFunc,
	AllocFuncFailed,
}

pub fn allocate_mem_lsa<T>(to_alloc: T, alloc_func_opt: &PLSA_ALLOCATE_LSA_HEAP) -> Result<*mut T, MemoryAllocationError> {
	let size = mem::size_of::<T>();
	let alloc_func = match alloc_func_opt {
		Some(af) => af,
		None => return Err(MemoryAllocationError::NoAllocFunc),
	};

	let mem_ptr = unsafe { alloc_func(size as u32) };

	if mem_ptr.is_null() {
		return Err(MemoryAllocationError::AllocFuncFailed);
	}

	let mem_ptr_cast: *mut T = mem_ptr.cast();

	unsafe {
		*mem_ptr_cast = to_alloc;
	}

	Ok(mem_ptr_cast)
}

pub fn allocate_mem_client<T>(to_alloc: T, alloc_func_opt: &PLSA_ALLOCATE_CLIENT_BUFFER, client_req: *const *const c_void) -> Result<*mut T, MemoryAllocationError> {
	let size = mem::size_of::<T>();
	let alloc_func = match alloc_func_opt {
		Some(af) => af,
		None => return Err(MemoryAllocationError::NoAllocFunc),
	};

	let mem_ptr: *mut *mut c_void = null_mut();
	
	match unsafe { alloc_func(client_req, size as u32, mem_ptr) } {
		STATUS_SUCCESS => (),
		_ => return Err(MemoryAllocationError::AllocFuncFailed),
	};

	if mem_ptr.is_null() {
		return Err(MemoryAllocationError::AllocFuncFailed);
	}

	let mem_ptr_cast: *mut T = mem_ptr.cast();

	unsafe {
		*mem_ptr_cast = to_alloc;
	}

	Ok(mem_ptr_cast)
}

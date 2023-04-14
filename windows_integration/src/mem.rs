use std::mem;

use windows::Win32::Security::Authentication::Identity::PLSA_ALLOCATE_LSA_HEAP;

pub enum MemoryAllocationError {
	NoAllocFunc,
	AllocFuncFailed,
}

pub fn allocate_mem<T>(to_alloc: T, alloc_func_opt: &PLSA_ALLOCATE_LSA_HEAP) -> Result<*mut T, MemoryAllocationError> {
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
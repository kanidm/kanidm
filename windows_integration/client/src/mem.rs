use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null_mut;

use windows::Win32::Foundation::{STATUS_SUCCESS, NTSTATUS};

pub type AllocateMemInLsaFn = unsafe extern "system" fn(length: u32) -> *mut ::core::ffi::c_void;
pub type AllocateMemInClientFn = unsafe extern "system" fn(client_request: *const *const ::core::ffi::c_void, length_required: u32, client_base_address: *mut *mut ::core::ffi::c_void) -> NTSTATUS;

pub enum MemoryAllocationError {
    AllocFuncFailed,
}

pub unsafe fn allocate_mem_lsa<T>(
    to_alloc: T,
    alloc_func: &AllocateMemInLsaFn,
) -> Result<*mut T, MemoryAllocationError> {
    let size = size_of::<T>();
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

pub unsafe fn allocate_mem_client<T>(
    to_alloc: T,
    alloc_func: &AllocateMemInClientFn,
    client_req: *const *const c_void,
) -> Result<*mut T, MemoryAllocationError> {
    let size = size_of::<T>();

    let mem_ptr: *mut *mut c_void = null_mut();

    if unsafe { alloc_func(client_req, size as u32, mem_ptr) } != STATUS_SUCCESS {
        return Err(MemoryAllocationError::AllocFuncFailed);
    }

    if mem_ptr.is_null() {
        return Err(MemoryAllocationError::AllocFuncFailed);
    }

    let mem_ptr_cast: *mut T = mem_ptr.cast();

    unsafe {
        *mem_ptr_cast = to_alloc;
    }

    Ok(mem_ptr_cast)
}

#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::ptr_offset_with_cast)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::useless_transmute)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::upper_case_acronyms)]
#![allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case
)]

include!(concat!(env!("OUT_DIR"), "/freeradius_bindings.rs"));


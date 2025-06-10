#![no_std]

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AllocInfo {
    pub pid: u32,
    pub size: u64,
    pub stack_id: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CombAllocInfo {
    pub total_size: u64,
    pub number_of_allocs: u32,
}

#![no_std]
#![no_main]

use aya_ebpf::{macros::uprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[repr(C)]
pub struct AllocEvent {
    pub pid: u32,
    pub size: u64,
    pub call_type: u8,
}

#[uprobe]
pub fn memmap(ctx: ProbeContext) -> u32 {
    match try_memmap(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_memmap(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function malloc called by libc");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

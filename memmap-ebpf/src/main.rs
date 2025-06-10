#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, StackTrace},
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::{error, info, warn};

#[map]
static SIZES: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map]
static ALLOCS: HashMap<u64, AllocInfo> = HashMap::with_max_entries(1_000_000, 0);

#[map]
static COMBINED_ALLOCS: HashMap<u64, CombAllocs> = HashMap::with_max_entries(1_000_000, 0);

#[map]
static MEMPTRS: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(10240, 0);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AllocInfo {
    pub pid: u32,
    pub size: u64,
    pub stack_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union CombAllocs {
    pub allocs: CombAllocInfo,
    pub bits: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CombAllocInfo {
    pub total_size: u64,
    pub number_of_allocs: u32,
}

#[uprobe]
pub fn malloc_enter(ctx: ProbeContext) -> u32 {
    let size = match ctx.arg::<usize>(0) {
        Some(size) => size,
        None => {
            error!(&ctx, "malloc_enter: Failed to get size argument");
            return 0;
        }
    };
    match gen_alloc_enter(&ctx, size) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "malloc_enter failed: {}", e);
            0
        }
    }
}

#[uretprobe]
pub fn malloc_exit(ctx: RetProbeContext) -> u32 {
    let address = match ctx.ret::<usize>() {
        Some(size) => size as u64,
        None => {
            error!(&ctx, "malloc_exit: Failed to get address argument");
            return 0;
        }
    };
    match gen_alloc_exit(&ctx, address) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "malloc_exit failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn free_enter(ctx: ProbeContext) -> u32 {
    let address = match ctx.arg::<u64>(0) {
        Some(address) => address,
        None => {
            error!(&ctx, "free_enter: Failed to get address argument");
            return 0;
        }
    };
    match gen_free_enter(&ctx, address) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "free_enter failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn calloc_enter(ctx: ProbeContext) -> u32 {
    let nmemb = match ctx.arg::<usize>(0) {
        Some(nmemb) => nmemb,
        None => {
            error!(&ctx, "calloc_enter: Failed to get nmemb argument");
            return 0;
        }
    };
    let size = match ctx.arg::<usize>(1) {
        Some(size) => size,
        None => {
            error!(&ctx, "calloc_enter: Failed to get size argument");
            return 0;
        }
    };
    match gen_alloc_enter(&ctx, nmemb * size) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "calloc_enter failed: {}", e);
            0
        }
    }
}

#[uretprobe]
pub fn calloc_exit(ctx: RetProbeContext) -> u32 {
    let address = match ctx.ret::<usize>() {
        Some(size) => size as u64,
        None => {
            error!(&ctx, "calloc_exit: Failed to get address argument");
            return 0;
        }
    };
    match gen_alloc_exit(&ctx, address) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "calloc_exit failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn realloc_enter(ctx: ProbeContext) -> u32 {
    let ptr = match ctx.arg::<u64>(0) {
        Some(ptr) => ptr,
        None => {
            error!(&ctx, "realloc_enter: Failed to get ptr argument");
            return 0;
        }
    };
    let size = match ctx.arg::<usize>(1) {
        Some(size) => size,
        None => {
            error!(&ctx, "realloc_enter: Failed to get size argument");
            return 0;
        }
    };
    match gen_free_enter(&ctx, ptr) {
        Ok(_) => {}
        Err(e) => {
            error!(&ctx, "realloc_enter free_enter failed: {}", e);
            return 0;
        }
    };
    match gen_alloc_enter(&ctx, size) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "realloc_enter failed: {}", e);
            0
        }
    }
}

#[uretprobe]
pub fn realloc_exit(ctx: RetProbeContext) -> u32 {
    let address = match ctx.ret::<usize>() {
        Some(size) => size as u64,
        None => {
            error!(&ctx, "realloc_exit: Failed to get address argument");
            return 0;
        }
    };
    match gen_alloc_exit(&ctx, address) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "realloc_exit failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn mmap_enter(ctx: ProbeContext) -> u32 {
    let size = match ctx.arg::<usize>(1) {
        Some(size) => size,
        None => {
            error!(&ctx, "mmap_enter: Failed to get the size argument");
            return 0;
        }
    };
    match gen_alloc_enter(&ctx, size) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "mmap_enter failed: {}", e);
            return 0;
        }
    }
}

#[uretprobe]
pub fn mmap_exit(ctx: RetProbeContext) -> u32 {
    let address = match ctx.ret::<usize>() {
        Some(size) => size as u64,
        None => {
            error!(&ctx, "mmap_exit: Failed to get address argument");
            return 0;
        }
    };
    match gen_alloc_exit(&ctx, address) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "mmap_exit failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn munmap_enter(ctx: ProbeContext) -> u32 {
    let address = match ctx.arg::<u64>(0) {
        Some(address) => address,
        None => {
            error!(&ctx, "munmap_enter: Failed to get address argument");
            return 0;
        }
    };
    match gen_free_enter(&ctx, address) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "munmap_enter failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn posix_memalign_enter(ctx: ProbeContext) -> u32 {
    let memptr = match ctx.arg::<usize>(0) {
        Some(memptr) => memptr,
        None => {
            error!(&ctx, "posix_memalign_enter: Failed to get memptr argument");
            return 0;
        }
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    MEMPTRS
        .insert(&pid, &(memptr as u64), 0)
        .unwrap_or_else(|e| {
            warn!(
                &ctx,
                "posix_memalign_enter: Failed to insert memptr for pid {}: {}", pid, e
            );
        });
    let size = match ctx.arg::<usize>(2) {
        Some(size) => size,
        None => {
            error!(&ctx, "posix_memalign_enter: Failed to get size argument");
            return 0;
        }
    };
    match gen_alloc_enter(&ctx, size) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "posix_memalign_enter failed: {}", e);
            0
        }
    }
}

#[uretprobe]
pub fn posix_memalign_exit(ctx: RetProbeContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let memptr = match unsafe { MEMPTRS.get(&pid) } {
        Some(memptr) => *memptr,
        None => {
            warn!(
                &ctx,
                "posix_memalign_exit: Failed to get memptr for pid {}", pid
            );
            return 0;
        }
    };
    MEMPTRS.remove(&pid).unwrap_or_else(|e| {
        warn!(
            &ctx,
            "posix_memalign_exit: Failed to remove memptr for pid {}: {}", pid, e
        );
    });
    let addr = match unsafe { bpf_probe_read_user(memptr as *const usize) } {
        Ok(memptr_value) => {
            info!(&ctx, "posix_memalign_exit: memptr = {}", memptr_value);
            memptr_value
        }
        Err(e) => {
            error!(
                &ctx,
                "posix_memalign_exit: Failed to read memptr value: {}", e
            );
            return 0;
        }
    };
    match gen_alloc_exit(&ctx, addr as u64) {
        Ok(ret) => {
            info!(&ctx, "posix_memalign_exit: ret = {}", ret);
            ret
        }
        Err(e) => {
            error!(&ctx, "posix_memalign_exit failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn aligned_alloc_enter(ctx: ProbeContext) -> u32 {
    let size = match ctx.arg::<usize>(1) {
        Some(size) => size,
        None => {
            error!(&ctx, "aligned_alloc_enter: Failed to get size argument");
            return 0;
        }
    };
    match gen_alloc_enter(&ctx, size) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "aligned_alloc_enter failed: {}", e);
            0
        }
    }
}

#[uretprobe]
pub fn aligned_alloc_exit(ctx: RetProbeContext) -> u32 {
    let address = match ctx.ret::<usize>() {
        Some(size) => size as u64,
        None => {
            warn!(&ctx, "aligned_alloc_exit: Failed to get address argument");
            return 0;
        }
    };
    match gen_alloc_exit(&ctx, address) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "aligned_alloc_exit failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn valloc_enter(ctx: ProbeContext) -> u32 {
    let size = match ctx.arg::<usize>(0) {
        Some(size) => size,
        None => {
            error!(&ctx, "valloc_enter: Failed to get size argument");
            return 0;
        }
    };
    match gen_alloc_enter(&ctx, size) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "valloc_enter failed: {}", e);
            0
        }
    }
}

#[uretprobe]
pub fn valloc_exit(ctx: RetProbeContext) -> u32 {
    let address = match ctx.ret::<usize>() {
        Some(size) => size as u64,
        None => {
            error!(&ctx, "valloc_exit: Failed to get address argument");
            return 0;
        }
    };
    match gen_alloc_exit(&ctx, address) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "valloc_exit failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn pvalloc_enter(ctx: ProbeContext) -> u32 {
    let size = match ctx.arg::<usize>(0) {
        Some(size) => size,
        None => {
            error!(&ctx, "pvalloc_enter: Failed to get size argument");
            return 0;
        }
    };
    match gen_alloc_enter(&ctx, size) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "pvalloc_enter failed: {}", e);
            0
        }
    }
}

#[uretprobe]
pub fn pvalloc_exit(ctx: RetProbeContext) -> u32 {
    let address = match ctx.ret::<usize>() {
        Some(size) => size as u64,
        None => {
            error!(&ctx, "pvalloc_exit: Failed to get address argument");
            return 0;
        }
    };
    match gen_alloc_exit(&ctx, address) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "pvalloc_exit failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn memalign_enter(ctx: ProbeContext) -> u32 {
    let size = match ctx.arg::<usize>(1) {
        Some(size) => size,
        None => {
            error!(&ctx, "memalign_enter: Failed to get size argument");
            return 0;
        }
    };
    match gen_alloc_enter(&ctx, size) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "memalign_enter failed: {}", e);
            0
        }
    }
}

#[uretprobe]
pub fn memalign_exit(ctx: RetProbeContext) -> u32 {
    let address = match ctx.ret::<usize>() {
        Some(size) => size as u64,
        None => {
            error!(&ctx, "memalign_exit: Failed to get address argument");
            return 0;
        }
    };
    match gen_alloc_exit(&ctx, address) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "memalign_exit failed: {}", e);
            0
        }
    }
}

fn update_statistics_add(ctx: &RetProbeContext, stack_id: u64, sz: u64) {
    let existing_cinfo = match COMBINED_ALLOCS.get_ptr_mut(&stack_id) {
        Some(cinfo) => cinfo,
        None => {
            error!(
                ctx,
                "No existing combined alloc info for stack_id {}", stack_id
            );
            return;
        }
    };

    let mut incremental_cinfo = CombAllocs {
        allocs: CombAllocInfo {
            total_size: sz,
            number_of_allocs: 1,
        },
    };

    unsafe { incremental_cinfo.bits += existing_cinfo.read().bits };

    match COMBINED_ALLOCS.insert(&stack_id, &incremental_cinfo, 0) {
        Ok(_) => info!(ctx, "Updated combined allocs for stack_id {}", stack_id),
        Err(e) => {
            error!(
                ctx,
                "Failed to update combined allocs for stack_id {}: {}", stack_id, e
            );
        }
    };
}

fn update_statistics_del(ctx: &ProbeContext, stack_id: u64, sz: u64) {
    let existing_cinfo = match COMBINED_ALLOCS.get_ptr_mut(&stack_id) {
        Some(cinfo) => cinfo,
        None => {
            error!(
                ctx,
                "Failed to lookup combined allocs for stack_id {}", stack_id
            );
            return;
        }
    };

    let decremental_cinfo = CombAllocs {
        allocs: CombAllocInfo {
            total_size: sz,
            number_of_allocs: 1,
        },
    };

    unsafe { existing_cinfo.read().bits -= decremental_cinfo.bits };
}

fn gen_alloc_enter(ctx: &ProbeContext, size: usize) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    match SIZES.insert(&pid, &(size as u64), 0) {
        Ok(_) => info!(ctx, "Inserted size {} for pid {}", size, pid),
        Err(e) => {
            error!(ctx, "Failed to insert size {} for pid {}: {}", size, pid, e);
            return Err(0);
        }
    };
    info!(ctx, "alloc entered, size = {}", size);
    Ok(0)
}

fn gen_alloc_exit(ctx: &RetProbeContext, address: u64) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let size = match unsafe { SIZES.get(&pid) } {
        Some(size) => {
            info!(ctx, "alloc exited, size = {}", *size);
            size
        }
        None => {
            error!(ctx, "Failed to get size for pid {}", pid);
            return Ok(0);
        }
    };

    let size = *size;

    match SIZES.remove(&pid) {
        Ok(_) => info!(ctx, "Removed size for pid {}", pid),
        Err(e) => {
            error!(ctx, "Failed to remove size for pid {}: {}", pid, e);
            return Err(0);
        }
    };

    if address != 0 {
        let alloc_info = AllocInfo {
            pid,
            size: size,
            stack_id: unsafe { STACK_TRACES.get_stackid(ctx, 0).unwrap_or(0) } as u64,
        };
        match ALLOCS.insert(&address, &alloc_info, 0) {
            Ok(_) => info!(ctx, "Inserted alloc info for address {}", address),
            Err(e) => {
                error!(
                    ctx,
                    "Failed to insert alloc info for address {}: {}", address, e
                );
                return Err(0);
            }
        }
        update_statistics_add(&ctx, alloc_info.stack_id, size);
    }

    info!(
        ctx,
        "Allocation exit for address {} completed with size {}", address, size
    );

    Ok(0)
}

fn gen_free_enter(ctx: &ProbeContext, address: u64) -> Result<u32, u32> {
    let info = match unsafe { ALLOCS.get(&address) } {
        Some(info) => info,
        None => {
            error!(ctx, "No alloc info found for address {}", address);
            return Ok(0);
        }
    };
    let info = *info;
    ALLOCS.remove(&address).unwrap_or_else(|e| {
        error!(
            ctx,
            "Failed to remove alloc info for address {}: {}", address, e
        );
    });
    update_statistics_del(&ctx, info.stack_id, info.size);
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    info!(
        ctx,
        "Free entered for address {} by pid {} with size {}", address, pid, info.size
    );
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

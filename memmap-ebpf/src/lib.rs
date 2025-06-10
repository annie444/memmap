#![no_std]

// This file exists to enable the library target.

pub mod kmalloc;
pub mod mm_page;
pub mod percpu;

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::map,
    maps::{HashMap, StackTrace},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use aya_log_ebpf::{error, info, warn};
use memmap_common::{AllocInfo, CombAllocInfo};

use self::{
    kmalloc::{
        trace_event_raw_kfree, trace_event_raw_kmalloc, trace_event_raw_kmem_cache_alloc,
        trace_event_raw_kmem_cache_free,
    },
    mm_page::{trace_event_raw_mm_page_alloc, trace_event_raw_mm_page_free},
    percpu::{trace_event_raw_percpu_alloc_percpu, trace_event_raw_percpu_free_percpu},
};

#[map]
pub static SIZES: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map]
pub static ALLOCS: HashMap<u64, AllocInfo> = HashMap::with_max_entries(1_000_000, 0);

#[map]
pub static COMBINED_ALLOCS: HashMap<u64, CombAllocInfo> = HashMap::with_max_entries(1_000_000, 0);

#[map]
pub static MEMPTRS: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map]
pub static STACK_TRACES: StackTrace = StackTrace::with_max_entries(10240, 0);

const PAGE_SIZE: usize = 4096;

static mut WA_MISSING_FREE: bool = false;

#[inline]
pub fn trace_event_kmalloc(ctx: &TracePointContext) -> Result<u32, u32> {
    let raw_event = match unsafe { ctx.read_at::<trace_event_raw_kmalloc>(0) } {
        Ok(event) => event,
        Err(e) => {
            error!(ctx, "Failed to read raw event: {}", e);
            return Err(0);
        }
    };

    if raw_event.ptr.is_null() {
        error!(ctx, "Received kmalloc with null pointer");
        return Err(0);
    }

    gen_trace_alloc(ctx, raw_event.ptr as u64, raw_event.bytes_alloc)
}

#[inline]
pub fn trace_event_kfree(ctx: &TracePointContext) -> Result<u32, u32> {
    let raw_event = match unsafe { ctx.read_at::<trace_event_raw_kfree>(0) } {
        Ok(event) => event,
        Err(e) => {
            error!(ctx, "Failed to read raw event: {}", e);
            return Err(0);
        }
    };

    if raw_event.ptr.is_null() {
        error!(ctx, "Received kfree with null pointer");
        return Err(0);
    }

    match gen_free_trace(ctx, raw_event.ptr as u64) {
        Ok(_) => info!(
            ctx,
            "Free trace for address {} completed", raw_event.ptr as u64
        ),
        Err(e) => {
            error!(ctx, "Failed to handle free trace: {}", e);
            return Err(0);
        }
    }

    Ok(0)
}

#[inline]
pub fn trace_event_kmem_cache_alloc(ctx: &TracePointContext) -> Result<u32, u32> {
    let raw_event = match unsafe { ctx.read_at::<trace_event_raw_kmem_cache_alloc>(0) } {
        Ok(event) => event,
        Err(e) => {
            error!(
                ctx,
                "Failed to get raw_kmem_cache_alloc from context: {}", e
            );
            return Err(0);
        }
    };

    if raw_event.ptr.is_null() {
        error!(ctx, "Received kmem_cache_alloc with null pointer");
        return Err(0);
    }

    gen_trace_alloc(ctx, raw_event.ptr as u64, raw_event.bytes_alloc)
}

#[inline]
pub fn trace_event_kmeme_cache_free(ctx: &TracePointContext) -> Result<u32, u32> {
    let raw_event = match unsafe { ctx.read_at::<trace_event_raw_kmem_cache_free>(0) } {
        Ok(event) => event,
        Err(e) => {
            error!(ctx, "Failed to get raw_kmem_cache_free from context: {}", e);
            return Err(0);
        }
    };

    if raw_event.ptr.is_null() {
        error!(ctx, "Received kmem_cache_free with null pointer");
        return Err(0);
    }

    match gen_free_trace(ctx, raw_event.ptr as u64) {
        Ok(_) => info!(
            ctx,
            "Free trace for address {} completed", raw_event.ptr as u64
        ),
        Err(e) => {
            error!(ctx, "Failed to handle free trace: {}", e);
            return Err(0);
        }
    }

    Ok(0)
}

#[inline]
pub fn trace_event_mm_page_alloc(ctx: &TracePointContext) -> Result<u32, u32> {
    // This function is not implemented yet.
    let raw_event = match unsafe { ctx.read_at::<trace_event_raw_mm_page_alloc>(0) } {
        Ok(event) => event,
        Err(e) => {
            error!(ctx, "Failed to read raw mm_page_alloc event: {}", e);
            return Err(0);
        }
    };
    match gen_alloc_enter_trace(ctx, PAGE_SIZE << raw_event.order) {
        Ok(_) => info!(
            ctx,
            "Allocation enter for order {} completed", raw_event.order
        ),
        Err(e) => {
            error!(ctx, "Failed to handle allocation enter: {}", e);
            return Err(0);
        }
    }

    match gen_alloc_exit_trace(ctx, raw_event.pfn) {
        Ok(_) => info!(
            ctx,
            "Allocation exit for address {} completed", raw_event.pfn
        ),
        Err(e) => {
            error!(ctx, "Failed to handle allocation exit: {}", e);
            return Err(0);
        }
    }

    Ok(0)
}

#[inline]
pub fn trace_event_mm_page_free(ctx: &TracePointContext) -> Result<u32, u32> {
    // This function is not implemented yet.
    let raw_event = match unsafe { ctx.read_at::<trace_event_raw_mm_page_free>(0) } {
        Ok(event) => event,
        Err(e) => {
            error!(ctx, "Failed to read raw mm_page_free event: {}", e);
            return Err(0);
        }
    };
    match gen_free_trace(ctx, raw_event.pfn) {
        Ok(_) => info!(ctx, "Free trace for address {} completed", raw_event.pfn),
        Err(e) => {
            error!(ctx, "Failed to handle free trace: {}", e);
            return Err(0);
        }
    }
    Ok(0)
}

#[inline]
pub fn trace_event_percpu_alloc(ctx: &TracePointContext) -> Result<u32, u32> {
    let raw_event = match unsafe { ctx.read_at::<trace_event_raw_percpu_alloc_percpu>(0) } {
        Ok(event) => event,
        Err(e) => {
            error!(ctx, "Failed to read raw percpu alloc event: {}", e);
            return Err(0);
        }
    };

    if raw_event.ptr.is_null() {
        error!(ctx, "Received percpu alloc with null pointer");
        return Err(0);
    }

    gen_trace_alloc(ctx, raw_event.ptr as u64, raw_event.bytes_alloc)
}

#[inline]
pub fn trace_event_percpu_free(ctx: &TracePointContext) -> Result<u32, u32> {
    let raw_event = match unsafe { ctx.read_at::<trace_event_raw_percpu_free_percpu>(0) } {
        Ok(event) => event,
        Err(e) => {
            error!(ctx, "Failed to read raw percpu free event: {}", e);
            return Err(0);
        }
    };

    if raw_event.ptr.is_null() {
        error!(ctx, "Received percpu free with null pointer");
        return Err(0);
    }

    match gen_free_trace(ctx, raw_event.ptr as u64) {
        Ok(_) => info!(
            ctx,
            "Free trace for address {} completed", raw_event.ptr as u64
        ),
        Err(e) => {
            error!(ctx, "Failed to handle free trace: {}", e);
            return Err(0);
        }
    }

    Ok(0)
}

pub fn gen_trace_alloc(ctx: &TracePointContext, ptr: u64, size: usize) -> Result<u32, u32> {
    unsafe {
        if WA_MISSING_FREE {
            match gen_free_trace(ctx, ptr as u64) {
                Ok(_) => info!(ctx, "Handled missing free for address {}", ptr as u64),
                Err(e) => {
                    error!(
                        ctx,
                        "Failed to handle missing free for address {}: {}", ptr as u64, e
                    );
                    return Err(0);
                }
            };
        }
    }

    match gen_alloc_enter_trace(ctx, size) {
        Ok(_) => info!(ctx, "Allocation enter for size {} completed", size),
        Err(e) => {
            error!(ctx, "Failed to handle allocation enter: {}", e);
            return Err(0);
        }
    }

    match gen_alloc_exit_trace(ctx, ptr as u64) {
        Ok(_) => info!(ctx, "Allocation exit for address {} completed", ptr as u64),
        Err(e) => {
            error!(ctx, "Failed to handle allocation exit: {}", e);
            return Err(0);
        }
    }
    Ok(0)
}

#[inline]
pub fn update_statistics_tp_add(ctx: &TracePointContext, stack_id: u64, sz: u64) {
    let existing_cinfo = unsafe {
        &mut *(match COMBINED_ALLOCS.get_ptr_mut(&stack_id) {
            Some(cinfo) => cinfo,
            None => {
                warn!(
                    ctx,
                    "No existing combined alloc info for stack_id {}", stack_id
                );
                let new_cinfo = CombAllocInfo {
                    total_size: sz,
                    number_of_allocs: 1,
                };
                let new = &raw const new_cinfo;
                new.cast_mut()
            }
        })
    };

    existing_cinfo.total_size += sz;
    existing_cinfo.number_of_allocs += 1;

    match COMBINED_ALLOCS.insert(&stack_id, &existing_cinfo, 0) {
        Ok(_) => info!(ctx, "Updated combined allocs for stack_id {}", stack_id),
        Err(e) => {
            error!(
                ctx,
                "Failed to update combined allocs for stack_id {}: {}", stack_id, e
            );
        }
    };
}

#[inline]
pub fn update_statistics_add(ctx: &RetProbeContext, stack_id: u64, sz: u64) {
    let existing_cinfo = unsafe {
        &mut *(match COMBINED_ALLOCS.get_ptr_mut(&stack_id) {
            Some(cinfo) => cinfo,
            None => {
                warn!(
                    ctx,
                    "No existing combined alloc info for stack_id {}", stack_id
                );
                let new_cinfo = CombAllocInfo {
                    total_size: sz,
                    number_of_allocs: 1,
                };
                let new = &raw const new_cinfo;
                new.cast_mut()
            }
        })
    };

    existing_cinfo.total_size += sz;
    existing_cinfo.number_of_allocs += 1;

    match COMBINED_ALLOCS.insert(&stack_id, &existing_cinfo, 0) {
        Ok(_) => info!(ctx, "Updated combined allocs for stack_id {}", stack_id),
        Err(e) => {
            error!(
                ctx,
                "Failed to update combined allocs for stack_id {}: {}", stack_id, e
            );
        }
    };
}

#[inline]
pub fn update_statistics_tp_del(ctx: &TracePointContext, stack_id: u64, sz: u64) {
    let existing_cinfo = match COMBINED_ALLOCS.get_ptr_mut(&stack_id) {
        Some(cinfo) => unsafe { &mut *cinfo },
        None => {
            warn!(
                ctx,
                "Failed to lookup combined allocs for stack_id {}", stack_id
            );
            return;
        }
    };

    existing_cinfo.total_size -= sz;
    existing_cinfo.number_of_allocs -= 1;
    match COMBINED_ALLOCS.insert(&stack_id, &existing_cinfo, 0) {
        Ok(_) => info!(ctx, "Updated combined allocs for stack_id {}", stack_id),
        Err(e) => {
            error!(
                ctx,
                "Failed to update combined allocs for stack_id {}: {}", stack_id, e
            );
        }
    };
}

#[inline]
pub fn update_statistics_del(ctx: &ProbeContext, stack_id: u64, sz: u64) {
    let existing_cinfo = match COMBINED_ALLOCS.get_ptr_mut(&stack_id) {
        Some(cinfo) => unsafe { &mut *cinfo },
        None => {
            warn!(
                ctx,
                "Failed to lookup combined allocs for stack_id {}", stack_id
            );
            return;
        }
    };

    existing_cinfo.total_size -= sz;
    existing_cinfo.number_of_allocs -= 1;
    match COMBINED_ALLOCS.insert(&stack_id, &existing_cinfo, 0) {
        Ok(_) => info!(ctx, "Updated combined allocs for stack_id {}", stack_id),
        Err(e) => {
            error!(
                ctx,
                "Failed to update combined allocs for stack_id {}: {}", stack_id, e
            );
        }
    };
}

#[inline]
pub fn gen_alloc_enter_trace(ctx: &TracePointContext, size: usize) -> Result<u32, u32> {
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

#[inline]
pub fn gen_alloc_enter(ctx: &ProbeContext, size: usize) -> Result<u32, u32> {
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

#[inline]
pub fn gen_alloc_exit(ctx: &RetProbeContext) -> Result<u32, u32> {
    let address = match ctx.ret::<usize>() {
        Some(addr) => addr as u64,
        None => {
            error!(ctx, "Failed to get return value from context");
            return Err(0);
        }
    };
    gen_alloc_exit2(ctx, address)
}

#[inline]
pub fn gen_alloc_exit2(ctx: &RetProbeContext, address: u64) -> Result<u32, u32> {
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

#[inline]
pub fn gen_alloc_exit_trace(ctx: &TracePointContext, address: u64) -> Result<u32, u32> {
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
        update_statistics_tp_add(&ctx, alloc_info.stack_id, size);
    }

    info!(
        ctx,
        "Allocation exit for address {} completed with size {}", address, size
    );

    Ok(0)
}

#[inline]
pub fn gen_free_enter(ctx: &ProbeContext) -> Result<u32, u32> {
    let address = match ctx.arg::<usize>(0) {
        Some(addr) => addr as u64,
        None => {
            error!(ctx, "Failed to get address from context");
            return Err(0);
        }
    };
    gen_free_enter2(ctx, address)
}

#[inline]
pub fn gen_free_trace(ctx: &TracePointContext, address: u64) -> Result<u32, u32> {
    let info = match unsafe { ALLOCS.get(&address) } {
        Some(info) => info,
        None => {
            error!(ctx, "No alloc info found for address {}", address);
            return Err(0);
        }
    };
    let info = *info;
    match ALLOCS.remove(&address) {
        Ok(_) => (),
        Err(e) => {
            error!(
                ctx,
                "Failed to remove alloc info for address {}: {}", address, e
            );
        }
    };
    update_statistics_tp_del(&ctx, info.stack_id, info.size);
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    info!(
        ctx,
        "Free entered for address {} by pid {} with size {}", address, pid, info.size
    );
    Ok(0)
}

#[inline]
pub fn gen_free_enter2(ctx: &ProbeContext, address: u64) -> Result<u32, u32> {
    let info = match unsafe { ALLOCS.get(&address) } {
        Some(info) => info,
        None => {
            error!(ctx, "No alloc info found for address {}", address);
            return Ok(0);
        }
    };
    let info = *info;
    match ALLOCS.remove(&address) {
        Ok(_) => (),
        Err(e) => {
            error!(
                ctx,
                "Failed to remove alloc info for address {}: {}", address, e
            );
            return Ok(0);
        }
    };
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

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::{tracepoint, uprobe, uretprobe},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use aya_log_ebpf::{error, info, warn};
use memmap_ebpf::{
    gen_alloc_enter, gen_alloc_exit, gen_alloc_exit2, gen_free_enter, gen_free_enter2,
    trace_event_kfree, trace_event_kmalloc, trace_event_kmem_cache_alloc,
    trace_event_kmeme_cache_free, trace_event_mm_page_alloc, trace_event_mm_page_free,
    trace_event_percpu_alloc, trace_event_percpu_free, MEMPTRS,
};

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
    match gen_alloc_exit(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "malloc_exit failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn free_enter(ctx: ProbeContext) -> u32 {
    match gen_free_enter(&ctx) {
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
    match gen_alloc_exit(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "calloc_exit failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn reallocarray_enter(ctx: ProbeContext) -> u32 {
    let address = match ctx.arg::<usize>(0) {
        Some(address) => address as u64,
        None => {
            error!(&ctx, "reallocarray_enter: Failed to get address argument");
            return 0;
        }
    };
    let nmemb = match ctx.arg::<usize>(1) {
        Some(nmemb) => nmemb,
        None => {
            error!(&ctx, "reallocarray_enter: Failed to get nmemb argument");
            return 0;
        }
    };
    let size = match ctx.arg::<usize>(2) {
        Some(size) => size,
        None => {
            error!(&ctx, "reallocarray_enter: Failed to get size argument");
            return 0;
        }
    };
    match gen_free_enter2(&ctx, address) {
        Ok(_) => {}
        Err(e) => {
            error!(&ctx, "realloc_enter free_enter failed: {}", e);
            return 0;
        }
    };
    match gen_alloc_enter(&ctx, nmemb * size) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "reallocarray_enter failed: {}", e);
            0
        }
    }
}

#[uretprobe]
pub fn reallocarray_exit(ctx: RetProbeContext) -> u32 {
    match gen_alloc_exit(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "reallocarray_exit failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn realloc_enter(ctx: ProbeContext) -> u32 {
    let ptr = match ctx.arg::<usize>(0) {
        Some(ptr) => ptr as u64,
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
    match gen_free_enter2(&ctx, ptr) {
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
    match gen_alloc_exit(&ctx) {
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
    match gen_alloc_exit(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "mmap_exit failed: {}", e);
            0
        }
    }
}

#[uprobe]
pub fn munmap_enter(ctx: ProbeContext) -> u32 {
    match gen_free_enter(&ctx) {
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
    match MEMPTRS.insert(&pid, &(memptr as u64), 0) {
        Ok(_) => (),
        Err(e) => {
            warn!(
                &ctx,
                "posix_memalign_enter: Failed to insert memptr for pid {}: {}", pid, e
            );
        }
    };
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
    match MEMPTRS.remove(&pid) {
        Ok(_) => (),
        Err(e) => warn!(
            &ctx,
            "posix_memalign_exit: Failed to remove memptr for pid {}: {}", pid, e
        ),
    };
    let addr: usize = match unsafe { bpf_probe_read_user(memptr as *const usize) } {
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
    match gen_alloc_exit2(&ctx, addr as u64) {
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
    match gen_alloc_exit(&ctx) {
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
    match gen_alloc_exit(&ctx) {
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
    match gen_alloc_exit(&ctx) {
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
    match gen_alloc_exit(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "memalign_exit failed: {}", e);
            0
        }
    }
}

#[tracepoint(category = "kmem", name = "kmalloc")]
pub fn memmap_kmalloc(ctx: TracePointContext) -> u32 {
    match trace_event_kmalloc(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "memmap_kmalloc failed: {}", e);
            0
        }
    }
}

#[tracepoint(category = "kmem", name = "kfree")]
pub fn memmap_kfree(ctx: TracePointContext) -> u32 {
    match trace_event_kfree(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "memmap_kfree failed: {}", e);
            0
        }
    }
}

#[tracepoint(category = "kmem", name = "kmem_cache_alloc")]
pub fn memmap_cache_alloc(ctx: TracePointContext) -> u32 {
    match trace_event_kmem_cache_alloc(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "memmap_kmem_cache_alloc failed: {}", e);
            0
        }
    }
}

#[tracepoint(category = "kmem", name = "kmem_cache_free")]
pub fn memmap_cache_free(ctx: TracePointContext) -> u32 {
    match trace_event_kmeme_cache_free(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "memmap_kmem_cache_free failed: {}", e);
            0
        }
    }
}

#[tracepoint(category = "kmem", name = "mm_page_alloc")]
pub fn memmap_mm_page_alloc(ctx: TracePointContext) -> u32 {
    // This tracepoint is not implemented in the original code, but you can add your own logic here.
    match trace_event_mm_page_alloc(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "memmap_mm_page_alloc failed: {}", e);
            0
        }
    }
}

#[tracepoint(category = "kmem", name = "mm_page_free")]
pub fn memmap_mm_page_free(ctx: TracePointContext) -> u32 {
    // This tracepoint is not implemented in the original code, but you can add your own logic here.
    match trace_event_mm_page_free(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "memmap_mm_page_free failed: {}", e);
            0
        }
    }
}

#[tracepoint(category = "percpu", name = "percpu_alloc_percpu")]
pub fn memmap_percpu_alloc(ctx: TracePointContext) -> u32 {
    // This tracepoint is not implemented in the original code, but you can add your own logic here.
    match trace_event_percpu_alloc(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "memmap_percpu_alloc failed: {}", e);
            0
        }
    }
}

#[tracepoint(category = "percpu", name = "percpu_free_percpu")]
pub fn memmap_percpu_free(ctx: TracePointContext) -> u32 {
    // This tracepoint is not implemented in the original code, but you can add your own logic here.
    match trace_event_percpu_free(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "memmap_percpu_free failed: {}", e);
            0
        }
    }
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

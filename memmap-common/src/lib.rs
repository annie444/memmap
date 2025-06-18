#![no_std]

use core::fmt;

// TODO:
// - [x] sys_enter_mmap
// - [x] sys_exit_mmap
// - [x] sys_enter_brk
// - [x] sys_exit_brk
// - [x] sys_enter_munmap
// - [x] sys_exit_munmap
// - [x] sys_enter_mremap
// - [x] sys_exit_mremap
// - [ ] mm:do_page_fault
// - [ ] vmscan:mm_vmscan_direct_reclaim_begin
// - [ ] vmscan:mm_vmscan_direct_reclaim_end
// - [ ] mm:page_free
// - [ ] mm:page_unmap
// - [ ] mm:page_release
// - [ ] zap_page_range
// - [ ] __free_pages_ok

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

/// name: sys_enter_brk
/// ID: 614
/// format:
///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
///         field:int common_pid;   offset:4;       size:4; signed:1;
///
///         field:int __syscall_nr; offset:8;       size:4; signed:1;
///         field:unsigned long brk;        offset:16;      size:8; signed:0;
///
/// print fmt: "brk: 0x%08lx", ((unsigned long)(REC->brk))
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysEnterBrk {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub __padding: i32, // 4 bytes padding
    pub brk: u64,
}

impl fmt::Display for SysEnterBrk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sys_enter_brk(brk: 0x{:08x})", self.brk)
    }
}

/// name: sys_enter_mmap
/// ID: 31
/// format:
///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
///         field:int common_pid;   offset:4;       size:4; signed:1;
///
///         field:int __syscall_nr; offset:8;       size:4; signed:1;
///         field:unsigned long addr;       offset:16;      size:8; signed:0;
///         field:unsigned long len;        offset:24;      size:8; signed:0;
///         field:unsigned long prot;       offset:32;      size:8; signed:0;
///         field:unsigned long flags;      offset:40;      size:8; signed:0;
///         field:unsigned long fd; offset:48;      size:8; signed:0;
///         field:unsigned long off;        offset:56;      size:8; signed:0;
///
/// print fmt: "addr: 0x%08lx, len: 0x%08lx, prot: 0x%08lx, flags: 0x%08lx, fd: 0x%08lx, off: 0x%08lx", ((unsigned long)(REC->addr)), ((unsigned long)(REC->len)), ((unsigned long)(REC->prot)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->fd)), ((unsigned long)(REC->off))
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysEnterMmap {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub __padding: i32, // 4 bytes padding
    pub addr: u64,
    pub len: u64,
    pub prot: u64,
    pub flags: u64,
    pub fd: u64,
    pub off: u64,
}

impl fmt::Display for SysEnterMmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sys_enter_mmap(addr: 0x{:08x}, len: 0x{:08x}, prot: 0x{:08x}, flags: 0x{:08x}, fd: 0x{:08x}, off: 0x{:08x})",
            self.addr, self.len, self.prot, self.flags, self.fd, self.off
        )
    }
}

/// name: sys_enter_munmap
/// ID: 612
/// format:
///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
///         field:int common_pid;   offset:4;       size:4; signed:1;
///
///         field:int __syscall_nr; offset:8;       size:4; signed:1;
///         field:unsigned long addr;       offset:16;      size:8; signed:0;
///         field:size_t len;       offset:24;      size:8; signed:0;
///
/// print fmt: "addr: 0x%08lx, len: 0x%08lx", ((unsigned long)(REC->addr)), ((unsigned long)(REC->len))
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysEnterMunmap {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub __padding: i32, // 4 bytes padding
    pub addr: u64,
    pub len: usize,
}

impl fmt::Display for SysEnterMunmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sys_enter_munmap(addr: 0x{:08x}, len: 0x{:08x})",
            self.addr, self.len
        )
    }
}

/// name: sys_enter_mremap
/// ID: 628
/// format:
///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
///         field:int common_pid;   offset:4;       size:4; signed:1;
///
///         field:int __syscall_nr; offset:8;       size:4; signed:1;
///         field:unsigned long addr;       offset:16;      size:8; signed:0;
///         field:unsigned long old_len;    offset:24;      size:8; signed:0;
///         field:unsigned long new_len;    offset:32;      size:8; signed:0;
///         field:unsigned long flags;      offset:40;      size:8; signed:0;
///         field:unsigned long new_addr;   offset:48;      size:8; signed:0;
///
/// print fmt: "addr: 0x%08lx, old_len: 0x%08lx, new_len: 0x%08lx, flags: 0x%08lx, new_addr: 0x%08lx", ((unsigned long)(REC->addr)), ((unsigned long)(REC->old_len)), ((unsigned long)(REC->new_len)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->new_addr))
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysEnterMremap {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub __padding: i32, // 4 bytes padding
    pub addr: u64,
    pub old_len: u64,
    pub new_len: u64,
    pub flags: u64,
    pub new_addr: u64,
}

impl fmt::Display for SysEnterMremap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sys_enter_mremap(addr: 0x{:08x}, old_len: 0x{:08x}, new_len: 0x{:08x}, flags: 0x{:08x}, new_addr: 0x{:08x})",
            self.addr, self.old_len, self.new_len, self.flags, self.new_addr
        )
    }
}

/// name: sys_exit_mmap
/// ID: 30
/// format:
///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
///         field:int common_pid;   offset:4;       size:4; signed:1;
///
///         field:int __syscall_nr; offset:8;       size:4; signed:1;
///         field:long ret; offset:16;      size:8; signed:1;
///
/// print fmt: "0x%lx", REC->ret
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysExitMmap {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub __padding: i32, // 4 bytes padding
    pub ret: i64,
}

impl fmt::Display for SysExitMmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sys_exit_mmap(ret: 0x{:x})", self.ret)
    }
}

/// name: sys_exit_brk
/// ID: 613
/// format:
///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
///         field:int common_pid;   offset:4;       size:4; signed:1;
///
///         field:int __syscall_nr; offset:8;       size:4; signed:1;
///         field:long ret; offset:16;      size:8; signed:1;
///
/// print fmt: "0x%lx", REC->ret
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysExitBrk {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub __padding: i32, // 4 bytes padding
    pub ret: i64,
}

impl fmt::Display for SysExitBrk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sys_exit_brk(ret: 0x{:x})", self.ret)
    }
}

/// name: sys_exit_munmap
/// ID: 611
/// format:
///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
///         field:int common_pid;   offset:4;       size:4; signed:1;
///
///         field:int __syscall_nr; offset:8;       size:4; signed:1;
///         field:long ret; offset:16;      size:8; signed:1;
///
/// print fmt: "0x%lx", REC->ret
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysExitMunmap {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub __padding: i32, // 4 bytes padding
    pub ret: i64,
}

impl fmt::Display for SysExitMunmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sys_exit_munmap(ret: 0x{:x})", self.ret)
    }
}

/// name: sys_exit_mremap
/// ID: 627
/// format:
///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
///         field:int common_pid;   offset:4;       size:4; signed:1;
///
///         field:int __syscall_nr; offset:8;       size:4; signed:1;
///         field:long ret; offset:16;      size:8; signed:1;
///
/// print fmt: "0x%lx", REC->ret
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysExitMremap {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub __padding: i32, // 4 bytes padding
    pub ret: i64,
}

impl fmt::Display for SysExitMremap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sys_exit_mremap(ret: 0x{:x})", self.ret)
    }
}

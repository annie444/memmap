use aya::programs::UProbe;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/memmap"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let Opt { pid } = opt;
    load_uprobe(&mut ebpf, "malloc_enter", "malloc", pid)?;
    load_uprobe(&mut ebpf, "malloc_exit", "malloc", pid)?;
    load_uprobe(&mut ebpf, "free_enter", "free", pid)?;
    load_uprobe(&mut ebpf, "calloc_enter", "calloc", pid)?;
    load_uprobe(&mut ebpf, "calloc_exit", "calloc", pid)?;
    load_uprobe(&mut ebpf, "realloc_enter", "realloc", pid)?;
    load_uprobe(&mut ebpf, "realloc_exit", "realloc", pid)?;
    load_uprobe(&mut ebpf, "mmap_enter", "mmap", pid)?;
    load_uprobe(&mut ebpf, "mmap_exit", "mmap", pid)?;
    load_uprobe(&mut ebpf, "munmap_enter", "munmap", pid)?;
    load_uprobe(&mut ebpf, "posix_memalign_enter", "posix_memalign", pid)?;
    load_uprobe(&mut ebpf, "posix_memalign_exit", "posix_memalign", pid)?;
    load_uprobe(&mut ebpf, "memalign_enter", "memalign", pid)?;
    load_uprobe(&mut ebpf, "memalign_exit", "memalign", pid)?;
    load_uprobe(&mut ebpf, "valloc_enter", "valloc", pid)?;
    load_uprobe(&mut ebpf, "valloc_exit", "valloc", pid)?;
    load_uprobe(&mut ebpf, "pvalloc_enter", "pvalloc", pid)?;
    load_uprobe(&mut ebpf, "pvalloc_exit", "pvalloc", pid)?;
    load_uprobe(&mut ebpf, "aligned_alloc_enter", "aligned_alloc", pid)?;
    load_uprobe(&mut ebpf, "aligned_alloc_exit", "aligned_alloc", pid)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn load_uprobe<'a>(
    ebpf: &'a mut aya::Ebpf,
    name: &'static str,
    symbol: &'static str,
    pid: Option<i32>,
) -> anyhow::Result<&'a mut UProbe> {
    let program: &'a mut UProbe = ebpf
        .program_mut(name)
        .ok_or_else(|| anyhow::anyhow!("Unable to find {name} in eBPF object file"))?
        .try_into()?;
    program.load()?;
    program.attach(Some(symbol), 0, "libc", pid)?;
    Ok(program)
}

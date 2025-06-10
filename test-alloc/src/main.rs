use std::{collections::HashMap, mem, num::NonZero, process, thread, time::Duration};

use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use rand::prelude::*;

#[derive(Parser, Debug)]
#[command(
    name = "test-alloc", 
    version, 
    about = "Allocates and over allocates a vector and a hash map for testing memory allocations.", 
    long_about = None
)]
struct Args {
    /// The size of the vector to allocate in MiB
    #[arg(short = 'v', long = "vector-size", default_value = "32")]
    vector_size: NonZero<usize>,
    /// The size of the hash map to allocate in entries
    #[arg(short = 'm', long = "map-size", default_value = "100000")]
    map_size: NonZero<usize>,
    /// The duration in seconds to spend on each allocation
    #[arg(short = 'd', long = "duration", default_value = "10")]
    duration: u64,
}

const MILLIS: u64 = 1000;
const MICROS: u64 = 1000 * MILLIS;
const NANOS: u64 = 1000 * MICROS;
const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

fn main() {
    let args = Args::parse();
    let mut rng = rand::rng();

    let style = ProgressStyle::with_template(
        "[{binary_bytes_per_sec}] {wide_bar:.cyan/blue} {binary_bytes} / {binary_total_bytes} {msg}"
    ).unwrap_or_else(|e| {
        eprintln!("Error creating progress style: {}", e);
        process::exit(1);
    }).progress_chars("=>-");

    let out = ProgressDrawTarget::stdout_with_hz(2);
    let mp = MultiProgress::with_draw_target(out);

    let _ = mp.println(format!(
        "Allocating a vector with {} MiB capacity and filling it with 8 MiB of data twice.",
        args.vector_size.get()
    ));

    let vector_cap = args.vector_size.get() * MIB;

    // Create a vector with a set capacity
    let mut vc = Vec::with_capacity(vector_cap);

    // Create a progress bar for the total fill
    let all = mp.add(ProgressBar::new((vector_cap * 2) as u64).with_style(style.clone()));
    all.set_message("Vector total fill");

    // Create a progress bar for the first fill
    let pb = mp.add(ProgressBar::new(vector_cap as u64).with_style(style.clone()));
    pb.set_message("Vector fill to capacity");

    
    let iter_duration: u64 = if args.duration == 0 {
        0
    } else {
        ((args.duration * NANOS) as f64 / vector_cap as f64).floor() as u64
    };

    let _ = mp.println(format!(
        "Filling the vector with {} iterations, each taking {} nanoseconds.",
        vector_cap, iter_duration
    ));

    // Fill the vector to the set capacity
    for _ in 0..vector_cap {
        let val = rng.random::<u8>();
        vc.push(val);
        pb.inc(1);
        all.inc(1);
        thread::sleep(Duration::from_nanos(iter_duration));
    }

    // Finish the progress bar and print a message
    pb.finish_with_message("Vector filled to capacity.");

    let _ = mp.println("Sleeping for 3 seconds...");
    thread::sleep(Duration::from_secs(3));

    // Create a new progress bar for the next fill
    let pb = mp.add(ProgressBar::new(vector_cap as u64).with_style(style.clone()));
    pb.set_message("Vector overfill");

    // Overfill the vector doubling its size
    for _ in 0..vector_cap {
        let val = rng.random::<u8>();
        vc.push(val);
        pb.inc(1);
        all.inc(1);
        thread::sleep(Duration::from_nanos(iter_duration));
    }

    // Finish the progress bar and print a message
    pb.finish_with_message("Vector filled to twice its capacity.");

    // Finalize the progress bar and print the total size
    all.finish_with_message(format!(
        "Total vector size: {} MiB",
        vc.len() * mem::size_of::<u8>() / MIB
    ));

    let _ = mp.println("Sleeping for 3 seconds before dropping the vector...");
    thread::sleep(Duration::from_secs(3));
    drop(vc);

    let _ = mp.println("Allocating a hash map with a set capacity and filling it twice.");

    let map_cap = args.map_size.get();

    // Create a hash map with a set capacity
    let mut hm: HashMap<usize, u8> = HashMap::with_capacity(map_cap);

    // Create a progress bar with twice the capacity of the hash map
    let all = mp.add(ProgressBar::new((map_cap * 2) as u64).with_style(style.clone()));
    all.set_message("Hash map total fill");

    // Create a progress bar with the capacity of the hash map
    let pb = mp.add(ProgressBar::new(map_cap as u64).with_style(style.clone()));
    pb.set_message("Fill the hash map to capacity");

    let iter_duration: u64 = if args.duration == 0 {
        0
    } else {
        ((args.duration * NANOS) as f64 / map_cap as f64).floor() as u64
    };

    for _ in 0..map_cap {
        let key = rng.random_range(0..usize::MAX);
        let val = rng.random::<u8>();
        hm.insert(key, val);
        all.inc(1);
        pb.inc(1);
        thread::sleep(Duration::from_nanos(iter_duration));
    }

    // Finish the progress bar and print a message
    pb.finish_with_message("Hash map filled to capacity.");

    let _ = mp.println("Sleeping for 3 seconds...");
    thread::sleep(Duration::from_secs(3));

    // Create a new progress bar for the overfill
    let pb = mp.add(ProgressBar::new(map_cap as u64).with_style(style.clone()));
    pb.set_message("Overfilling the hash map");

    for _ in 0..map_cap {
        let key = rng.random_range(0..usize::MAX);
        let val = rng.random::<u8>();
        hm.insert(key, val);
        all.inc(1);
        pb.inc(1);
        thread::sleep(Duration::from_nanos(iter_duration));
    }

    // Finish the progress bar and print a message
    pb.finish_with_message("Hash map filled to twice its capacity.");

    // Finalize the progress bar and print the total size
    all.finish_with_message(format!(
        "Hash map filled with a total of {} entries.",
        hm.len()
    ));

    let _ = mp.println("Sleeping for 3 seconds before dropping the hash map...");
    thread::sleep(Duration::from_secs(3));

    // Drop the hash map
    drop(hm);

    let _ = mp.println("All allocations completed. Exiting...");
    thread::sleep(Duration::from_secs(1));

    let _ = mp.clear();
}

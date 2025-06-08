use std::num::NonZero;

use clap::Parser;

#[derive(Debug, Parser)]
struct Args {
    #[arg(help = "Step in bytes to increase on each loop.")]
    step: NonZero<usize>,
    #[arg(help = "Report each n>0 iterations.")]
    report: NonZero<usize>,
}

fn main() {
    let args = Args::parse();

    #[allow(clippy::infinite_iter)]
    (1..)
        .inspect(|_| {
            std::hint::black_box(Box::leak(Box::<[u8]>::new_uninit_slice(args.step.get())));
        })
        .step_by(args.report.get())
        .for_each(|iteration| {
            println!("Reserved {} bytes", iteration * args.step.get());
        });
}

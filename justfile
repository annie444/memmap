
default:
  just --list

[doc("Install dependencies and tools for BPF development")]
setup:
  rustup install stable
  rustup toolchain install nightly --component rust-src
  just install-llvm
  just install-bpf-linker
  just install-lima
  just cargo-install cargo-wizard
  just cargo-install cargo-generate
  just cargo-install bindgen-cli
  just install-aya-tool
  
[private]
install-aya-tool:
  #!/usr/bin/env bash
  set -euo pipefail
  if ! command -v aya-tool &>/dev/null; then
    echo "Installing aya-tool..."
    cargo install --git https://github.com/aya-rs/aya -- aya-tool
  fi


[private]
cargo-install package:
  #!/usr/bin/env bash
  set -euo pipefail
  if ! command -v {{ package }} &>/dev/null; then
    cargo install {{ package }}
  fi

[private]
install-llvm:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ "{{ os() }}" = "linux" ]; then
    if ! command -v llvm-config &>/dev/null; then
      echo "Installing LLVM..."
      if command -v apt-get &>/dev/null; then
        sudo apt-get update && sudo apt-get install -y llvm-dev libclang-dev clang
      elif command -v dnf &>/dev/null; then
        sudo dnf update -y && sudo dnf install -y llvm llvm-devel clang clang-devel
      else
        echo "Unsupported package manager. Please install LLVM manually."
        exit 1
      fi
    fi
  elif [ "{{ os() }}" = "macos" ]; then
    if ! command -v llvm-config &>/dev/null; then
      echo "Installing LLVM..."
      brew install llvm
    fi
  else
    echo "Unsupported OS: {{ os() }}"
    exit 1
  fi

[private]
install-bpf-linker:
  #!/usr/bin/env bash
  set -euo pipefail
  if ! command -v bpf-linker &>/dev/null; then
    echo "Installing bpf-linker..."
    if [ "{{ os() }}" = "linux" ]; then
      cargo install bpf-linker
    elif [ "{{ os() }}" = "macos" ]; then
      LLVM_SYS_180_PREFIX=$(brew --prefix llvm) cargo install \
        --no-default-features bpf-linker
    else
      echo "bpf-linker is only supported on Linux and macOS."
      exit 1
    fi
  fi

[private]
install-lima:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ "{{ os() }}" = "macos" ]; then
    if ! command -v limactl &>/dev/null; then
      echo "Installing Lima..."
      brew install lima
    fi
  else
    echo "Lima is only required on macOS."
  fi

[doc("Add dependencies to the given package")]
[group("cargo")]
add package *args:
  cargo add --package {{ package }} {{ args }}

[doc("Enter the shell of the BPF VM")]
[group("vm")]
shell:
  limactl shell bpf-vm

[doc("Create the BPF VM")]
[group("vm")]
create:
  limactl create --name bpf-vm bpf-vm.yaml

[doc("Start the BPF VM")]
[group("vm")]
start:
  limactl start bpf-vm

[doc("Stop the BPF VM")]
[group("vm")]
stop:
  limactl stop bpf-vm

[doc("Run the test-alloc package with optional arguments.")]
[group("cargo")]
test *args:
  cargo run --package test-alloc -- {{ args }}

[doc("Run the memmap package with optional arguments.")]
[group("cargo")]
run *args:
  #!/usr/bin/env bash
  set -euo pipefail
  export RUST_LOG=info
  export RUST_BACKTRACE=full
  cargo run --package memmap -- {{ args }}

[doc("Run the memmap package as root with optional arguments.")]
[group("cargo")]
sudo *args:
  #!/usr/bin/env bash
  set -euo pipefail
  export RUST_LOG=info
  export RUST_BACKTRACE=full
  sudo --preserve-env=RUST_BACKTRACE,RUST_LOG,PATH,LD_LIBRARY_PATH,LIBRARY_PATH,CPATH,PKG_CONFIG_PATH /root/.cargo/bin/cargo run --package memmap --release -- {{ args }}

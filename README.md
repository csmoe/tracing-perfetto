tracing-perfetto
======

# Overview

tracing-perfetto is a Layer for [tracing-subscriber](https://crates.io/crates/tracing-subscriber) that outputs traces in perfetto's trace packet format that can be viewed with [ui.perfetto.dev](https://ui.perfetto.dev).

## Usage

Add this near the beginning of `main`:
```rust
use tracing_perfetto::PerfettoLayer;
use tracing_subscriber::{registry::Registry, prelude::*};

let layer = PerfettoLayer::new(std::sync::Mutex::new(std::fs::File::create("/tmp/test.pftrace").unwrap()));
tracing_subscriber::registry().with(layer).init();
```
Open that file with [ui.perfetto.dev](https://ui.perfetto.dev):

![](./doc/images/pftrace-screenshot.png)


## Upgrade `perfetto_trace.proto`

1. Download the latest [perfetto_trace.proto](https://github.com/google/perfetto/blob/main/protos/perfetto/trace/perfetto_trace.proto) into `protos/peffetto_trace.proto`.

2. Run `upgrade.rs`
    - Windows `cargo +nightly -Zscript upgrade.rs`
    - *nix `./upgrade.rs`

3. Create a pull request with the changes.

# License

Licensed under the [MIT license](https://opensource.org/license/mit).

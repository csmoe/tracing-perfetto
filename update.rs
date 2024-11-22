#!/usr/bin/env -S RUSTFLAGS=-Copt-level=3 cargo +nightly -Zscript
---cargo
[dependencies]
protobuf-src = "2.0.1"
prost-build = "0"
---

fn main() -> std::io::Result<()> {
    // https://github.com/google/perfetto/blob/main/protos/perfetto/trace/perfetto_trace.proto
    prost_build::Config::new()
        .format(true)
        .protoc_executable(protobuf_src::protoc())
        .out_dir("src/")
        .compile_protos(&["protos/perfetto_trace.proto"], &["protos"])?;
    Ok(())
}

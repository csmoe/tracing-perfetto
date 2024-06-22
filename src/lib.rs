use tracing::Id;
use tracing_subscriber::Layer;

mod idl {
    include!(concat!(env!("OUT_DIR"), "/perfetto.protos.rs"));
}

pub struct Config {}

pub struct PerfettoSubscriber {}

pub struct Builder {}

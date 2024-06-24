#![forbid(unsafe_code)]

use bytes::BufMut;
use core::fmt;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::io::Write;
use tracing::field::Field;
use tracing::field::Visit;
use tracing::span;
use tracing::span::Attributes;
use tracing::span::Record;
use tracing::Event;
use tracing::Id;
use tracing::Metadata;
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

mod idl {
    include!(concat!(env!("OUT_DIR"), "/perfetto.protos.rs"));
}

pub struct Config {}

pub struct PerfettoSubscriber {
    sequence_id: tracing::Id,
}

pub struct Builder {}

impl PerfettoSubscriber {
    pub fn new() -> Self {
        Self {}
    }
}

impl<S: Subscriber> Layer<S> for TracelogSubscriber
where
    S: for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {}
}

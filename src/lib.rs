#![forbid(unsafe_code)]

use bytes::{BufMut, Bytes, BytesMut};
use core::fmt;
use prost::Message;
use std::io::Write;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tracing::field::Field;
use tracing::field::Visit;
use tracing::span;
use tracing::span::Attributes;
use tracing::span::Record;
use tracing::Event;
use tracing::Id;
use tracing::Metadata;
use tracing::Subscriber;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

mod idl {
    include!(concat!(env!("OUT_DIR"), "/perfetto.protos.rs"));
}

thread_local! {
    static THREAD_TRACK_UUID: AtomicU64 = AtomicU64::new(rand::random::<u64>());
    static THREAD_DESCRIPTOR_SENT: AtomicBool = AtomicBool::new(false);
}

static PROCESS_DESCRIPTOR_SENT: AtomicBool = AtomicBool::new(false);

pub struct Config {}

pub struct PerfettoSubscriber<W = fn() -> std::io::Stdout> {
    sequence_id: SequenceId,
    track_uuid: TrackUuid,
    writer: W,
}

impl<W: for<'writer> MakeWriter<'writer> + 'static> PerfettoSubscriber<W> {
    pub fn new(writer: W) -> Self {
        Self {
            sequence_id: SequenceId::new(NonZeroU64::new(rand::random()).unwrap()),
            track_uuid: TrackUuid::new(NonZeroU64::new(rand::random()).unwrap()),
            writer,
        }
    }

    fn write_log(&self, log: idl::Trace) {
        let mut buf = BytesMut::new();
        let Ok(_) = log.encode(&mut buf) else {
            return;
        };
        self.writer.make_writer().write_all(&buf).unwrap();
    }
}

struct SequenceId(NonZeroU64);

impl SequenceId {
    fn new(n: NonZeroU64) -> Self {
        Self(n)
    }

    fn get(&self) -> u64 {
        self.0.get()
    }
}

struct TrackUuid(NonZeroU64);

impl TrackUuid {
    fn new(n: NonZeroU64) -> Self {
        Self(n)
    }

    fn get(&self) -> u64 {
        self.0.get()
    }
}

impl<W, S: Subscriber> Layer<S> for PerfettoSubscriber<W>
where
    S: for<'a> LookupSpan<'a>,
    W: for<'writer> MakeWriter<'writer> + 'static,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };

        let mut packets: Vec<idl::TracePacket> = Vec::with_capacity(2);
        let process_first_frame_sent = PROCESS_DESCRIPTOR_SENT.fetch_or(true, Ordering::SeqCst);
        if !process_first_frame_sent {
            let mut packet = idl::TracePacket::default();
            packet.optional_trusted_uid = Some(idl::trace_packet::OptionalTrustedUid::TrustedUid(
                self.sequence_id.get() as _,
            ));
            let process = create_process_descriptor().into();
            let track_desc = create_track_descriptor(
                self.track_uuid.get().into(),
                None,
                None::<&str>,
                process,
                None,
                None,
            );
            packet.data = Some(idl::trace_packet::Data::TrackDescriptor(track_desc));
            packets.push(packet);
        }

        let thread_first_frame_sent =
            THREAD_DESCRIPTOR_SENT.with(|v| v.fetch_or(true, Ordering::SeqCst));
        let thread_track_uuid = THREAD_TRACK_UUID.with(|id| id.load(Ordering::Relaxed));
        if !thread_first_frame_sent {
            let mut packet = idl::TracePacket::default();
            packet.optional_trusted_uid = Some(idl::trace_packet::OptionalTrustedUid::TrustedUid(
                self.sequence_id.get() as _,
            ));
            let thread = create_thread_descriptor().into();
            let track_desc = create_track_descriptor(
                thread_track_uuid.into(),
                self.track_uuid.get().into(),
                None::<&str>,
                None,
                thread,
                None,
            );
            packet.data = Some(idl::trace_packet::Data::TrackDescriptor(track_desc));
            packets.push(packet);
        }

        let mut packet = idl::TracePacket::default();
        let event = create_event(
            thread_track_uuid,
            Some(span.name()),
            span.metadata().file().zip(span.metadata().line()),
            Some(idl::track_event::Type::SliceBegin),
        );
        packet.data = Some(idl::trace_packet::Data::TrackEvent(event));
        packet.timestamp = chrono::Local::now().timestamp_nanos_opt().map(|t| t as _);
        packet.trusted_pid = Some(std::process::id() as _);
        packet.optional_trusted_packet_sequence_id = Some(
            idl::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                self.sequence_id.get() as _,
            ),
        );
        packets.push(packet);
        span.extensions_mut().insert(packets);
    }

    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let location = metadata.file().zip(metadata.line());
        let event = THREAD_TRACK_UUID.with(|id| {
            create_event(
                id.load(Ordering::Relaxed),
                Some(metadata.name()),
                location,
                Some(idl::track_event::Type::Instant),
            )
        });
        let mut packet = idl::TracePacket::default();
        packet.data = Some(idl::trace_packet::Data::TrackEvent(event));
        packet.trusted_pid = Some(std::process::id() as _);
        packet.timestamp = chrono::Local::now().timestamp_nanos_opt().map(|t| t as _);
        packet.optional_trusted_packet_sequence_id = Some(
            idl::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                self.sequence_id.get() as _,
            ),
        );
        let trace = idl::Trace {
            packet: vec![packet],
        };
        self.write_log(trace);
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let Some(mut packets) = span.extensions_mut().remove::<Vec<idl::TracePacket>>() else {
            return;
        };

        let mut packet = idl::TracePacket::default();
        let event = THREAD_TRACK_UUID.with(|id| {
            create_event(
                id.load(Ordering::Relaxed),
                Some(span.metadata().name()),
                span.metadata().file().zip(span.metadata().line()),
                Some(idl::track_event::Type::SliceEnd),
            )
        });
        packet.data = Some(idl::trace_packet::Data::TrackEvent(event));
        packet.timestamp = chrono::Local::now().timestamp_nanos_opt().map(|t| t as _);
        packet.trusted_pid = Some(std::process::id() as _);
        packet.optional_trusted_packet_sequence_id = Some(
            idl::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                self.sequence_id.get() as _,
            ),
        );
        packets.push(packet);
        let trace = idl::Trace { packet: packets };

        self.write_log(trace);
    }
}

fn create_thread_descriptor() -> idl::ThreadDescriptor {
    let mut thread = idl::ThreadDescriptor::default();
    thread.pid = Some(std::process::id() as _);
    thread.tid = Some(thread_id::get() as _);
    thread.thread_name = std::thread::current().name().map(|n| n.to_string());
    thread
}

fn create_process_descriptor() -> idl::ProcessDescriptor {
    let mut process = idl::ProcessDescriptor::default();
    process.pid = Some(std::process::id() as _);
    process
}

fn create_track_descriptor(
    uuid: Option<u64>,
    parent_uuid: Option<u64>,
    name: Option<impl AsRef<str>>,
    process: Option<idl::ProcessDescriptor>,
    thread: Option<idl::ThreadDescriptor>,
    counter: Option<idl::CounterDescriptor>,
) -> idl::TrackDescriptor {
    let mut desc = idl::TrackDescriptor::default();
    desc.uuid = uuid;
    desc.parent_uuid = parent_uuid;
    desc.static_or_dynamic_name = name
        .map(|s| s.as_ref().to_string())
        .map(idl::track_descriptor::StaticOrDynamicName::Name);
    desc.process = process;
    desc.thread = thread;
    desc.counter = counter;
    desc
}

fn create_event(
    track_uuid: u64,
    name: Option<&str>,
    location: Option<(&str, u32)>,
    r#type: Option<idl::track_event::Type>,
) -> idl::TrackEvent {
    let mut event = idl::TrackEvent::default();
    event.track_uuid = Some(track_uuid);
    if let Some(name) = name {
        event.name_field = Some(idl::track_event::NameField::Name(name.to_string()));
    }
    if let Some(t) = r#type {
        event.set_type(t);
    }
    if let Some((file, line)) = location {
        let mut source_location = idl::SourceLocation::default();
        source_location.file_name = Some(file.to_owned());
        source_location.line_number = Some(line);
        let location = idl::track_event::SourceLocationField::SourceLocation(source_location);
        event.source_location_field = Some(location);
    }
    event
}

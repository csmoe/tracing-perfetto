#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]
#![forbid(unsafe_code)]

use bytes::BytesMut;
use prost::Message;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tracing::field::Field;
use tracing::field::Visit;
use tracing::span;
use tracing::Event;
use tracing::Id;
use tracing::Subscriber;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

#[path = "perfetto.protos.rs"]
#[allow(clippy::all)]
#[rustfmt::skip]
mod idl;

thread_local! {
    static THREAD_TRACK_UUID: AtomicU64 = AtomicU64::new(rand::random::<u64>());
    static THREAD_DESCRIPTOR_SENT: AtomicBool = const { AtomicBool::new(false) };
}

// This is thread safe, since duplicated descriptor will be combined into one by perfetto.
static PROCESS_DESCRIPTOR_SENT: AtomicBool = AtomicBool::new(false);

/// A `Layer` that records span as perfetto's
/// `TYPE_SLICE_BEGIN`/`TYPE_SLICE_END`, and event as `TYPE_INSTANT`.
///
/// `PerfettoLayer` will output the records as encoded [protobuf messages](https://github.com/google/perfetto).
pub struct PerfettoLayer<W = fn() -> std::io::Stdout> {
    sequence_id: SequenceId,
    track_uuid: TrackUuid,
    writer: W,
    config: Config,
}

/// Writes encoded records into provided instance.
///
/// This is implemented for types implements [`MakeWriter`].
pub trait PerfettoWriter {
    fn write_log(&self, buf: BytesMut) -> std::io::Result<()>;
}

impl<W: for<'writer> MakeWriter<'writer> + 'static> PerfettoWriter for W {
    fn write_log(&self, buf: BytesMut) -> std::io::Result<()> {
        self.make_writer().write_all(&buf)
    }
}

#[derive(Default)]
struct Config {
    debug_annotations: bool,
    filter: Option<fn(&str) -> bool>,
}

impl<W: PerfettoWriter> PerfettoLayer<W> {
    pub fn new(writer: W) -> Self {
        Self {
            sequence_id: SequenceId::new(rand::random()),
            track_uuid: TrackUuid::new(rand::random()),
            writer,
            config: Config::default(),
        }
    }

    /// Configures whether or not spans/events should be recorded with their metadata and fields.
    pub fn with_debug_annotations(mut self, value: bool) -> Self {
        self.config.debug_annotations = value;
        self
    }

    /// Configures whether or not spans/events be recorded based on the occurrence of a field name.
    ///
    /// Sometimes, not all the events/spans should be treated as perfetto trace, you can append a
    /// field to indicate that this even/span should be captured into trace:
    ///
    /// ```rust
    /// use tracing_perfetto::PerfettoLayer;
    /// use tracing_subscriber::{layer::SubscriberExt, Registry, prelude::*};
    ///
    /// let layer = PerfettoLayer::new(std::fs::File::open("/tmp/test.pftrace").unwrap())
    ///                 .with_filter_by_marker(|field_name| field_name == "perfetto");
    /// tracing_subscriber::registry().with(layer).init();
    ///
    /// // this event will be record, as it contains a `perfetto` field
    /// tracing::info!(perfetto = true, my_bool = true);
    ///
    /// // this span will be record, as it contains a `perfetto` field
    /// #[tracing::instrument(fields(perfetto = true))]
    /// fn to_instr() {
    ///
    ///   // this event will be ignored
    ///   tracing::info!(my_bool = true);
    /// }
    /// ```
    pub fn with_filter_by_marker(mut self, filter: fn(&str) -> bool) -> Self {
        self.config.filter = Some(filter);
        self
    }

    fn thread_descriptor(&self) -> Option<idl::TracePacket> {
        let thread_first_frame_sent =
            THREAD_DESCRIPTOR_SENT.with(|v| v.fetch_or(true, Ordering::SeqCst));
        if thread_first_frame_sent {
            return None;
        }
        let thread_track_uuid = THREAD_TRACK_UUID.with(|id| id.load(Ordering::Relaxed));
        let mut packet = idl::TracePacket::default();
        let thread = create_thread_descriptor().into();
        let track_desc = create_track_descriptor(
            thread_track_uuid.into(),
            None,
            std::thread::current().name(),
            None,
            thread,
            None,
        );
        packet.data = Some(idl::trace_packet::Data::TrackDescriptor(track_desc));
        Some(packet)
    }

    fn process_descriptor(&self) -> Option<idl::TracePacket> {
        let process_first_frame_sent = PROCESS_DESCRIPTOR_SENT.fetch_or(true, Ordering::SeqCst);
        if process_first_frame_sent {
            return None;
        }
        let mut packet = idl::TracePacket::default();
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
        Some(packet)
    }

    fn write_log(&self, mut log: idl::Trace) {
        let mut buf = BytesMut::new();

        if let Some(p) = self.process_descriptor() {
            log.packet.insert(0, p);
        }
        if let Some(t) = self.thread_descriptor() {
            log.packet.insert(1, t);
        }

        let Ok(_) = log.encode(&mut buf) else {
            return;
        };
        _ = self.writer.write_log(buf);
    }
}

struct SequenceId(u64);

impl SequenceId {
    fn new(n: u64) -> Self {
        Self(n)
    }

    fn get(&self) -> u64 {
        self.0
    }
}

struct TrackUuid(u64);

impl TrackUuid {
    fn new(n: u64) -> Self {
        Self(n)
    }

    fn get(&self) -> u64 {
        self.0
    }
}

struct PerfettoVisitor {
    perfetto: bool,
    filter: fn(&str) -> bool,
}

impl PerfettoVisitor {
    fn new(filter: fn(&str) -> bool) -> PerfettoVisitor {
        Self {
            filter,
            perfetto: false,
        }
    }
}

impl Visit for PerfettoVisitor {
    fn record_debug(&mut self, field: &Field, _value: &dyn std::fmt::Debug) {
        if (self.filter)(field.name()) {
            self.perfetto = true;
        }
    }
}

impl<W, S: Subscriber> Layer<S> for PerfettoLayer<W>
where
    S: for<'a> LookupSpan<'a>,
    W: for<'writer> MakeWriter<'writer> + 'static,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };

        let enabled = self
            .config
            .filter
            .map(|f| {
                let mut visitor = PerfettoVisitor::new(f);
                attrs.record(&mut visitor);
                visitor.perfetto
            })
            .unwrap_or(true);

        if !enabled {
            return;
        }

        let mut debug_annotations = DebugAnnotations::default();
        if self.config.debug_annotations {
            attrs.record(&mut debug_annotations);
        }

        let mut packet = idl::TracePacket::default();
        let thread_track_uuid = THREAD_TRACK_UUID.with(|id| id.load(Ordering::Relaxed));
        let event = create_event(
            thread_track_uuid,
            Some(span.name()),
            span.metadata().file().zip(span.metadata().line()),
            debug_annotations,
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
        span.extensions_mut().insert(idl::Trace {
            packet: vec![packet],
        });
    }

    fn on_record(&self, span: &span::Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(span) else {
            return;
        };

        // We don't check the filter here -- we've already checked it when we handled the span on
        // `on_new_span`. Iff we successfully attached a track packet to the span, then we'll also
        // update the trace packet with the debug data here.
        if let Some(extension) = span.extensions_mut().get_mut::<idl::Trace>() {
            if let Some(idl::trace_packet::Data::TrackEvent(ref mut event)) =
                &mut extension.packet[0].data
            {
                let mut debug_annotations = DebugAnnotations::default();
                values.record(&mut debug_annotations);
                event
                    .debug_annotations
                    .append(&mut debug_annotations.annotations);
            }
        };
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let enabled = self
            .config
            .filter
            .map(|f| {
                let mut visitor = PerfettoVisitor::new(f);
                event.record(&mut visitor);
                visitor.perfetto
            })
            .unwrap_or(true);

        if !enabled {
            return;
        }

        let metadata = event.metadata();
        let location = metadata.file().zip(metadata.line());

        let mut debug_annotations = DebugAnnotations::default();

        if self.config.debug_annotations {
            event.record(&mut debug_annotations);
        }

        let track_event = THREAD_TRACK_UUID.with(|id| {
            create_event(
                id.load(Ordering::Relaxed),
                Some(metadata.name()),
                location,
                debug_annotations,
                Some(idl::track_event::Type::Instant),
            )
        });
        let mut packet = idl::TracePacket::default();
        packet.data = Some(idl::trace_packet::Data::TrackEvent(track_event));
        packet.trusted_pid = Some(std::process::id() as _);
        packet.timestamp = chrono::Local::now().timestamp_nanos_opt().map(|t| t as _);
        packet.optional_trusted_packet_sequence_id = Some(
            idl::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                self.sequence_id.get() as _,
            ),
        );

        if let Some(span) = ctx.event_span(event) {
            if let Some(trace) = span.extensions_mut().get_mut::<idl::Trace>() {
                trace.packet.push(packet);
                return;
            }
        }
        let trace = idl::Trace {
            packet: vec![packet],
        };
        self.write_log(trace);
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };

        let Some(mut trace) = span.extensions_mut().remove::<idl::Trace>() else {
            return;
        };

        let debug_annotations = DebugAnnotations::default();

        let mut packet = idl::TracePacket::default();
        let meta = span.metadata();
        let event = THREAD_TRACK_UUID.with(|id| {
            create_event(
                id.load(Ordering::Relaxed),
                Some(meta.name()),
                meta.file().zip(meta.line()),
                debug_annotations,
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
        trace.packet.push(packet);

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
    debug_annotations: DebugAnnotations,
    r#type: Option<idl::track_event::Type>,
) -> idl::TrackEvent {
    let mut event = idl::TrackEvent::default();
    event.track_uuid = Some(track_uuid);
    event.categories = vec!["".to_string()];
    if let Some(name) = name {
        event.name_field = Some(idl::track_event::NameField::Name(name.to_string()));
    }
    if let Some(t) = r#type {
        event.set_type(t);
    }
    if !debug_annotations.annotations.is_empty() {
        event.debug_annotations = debug_annotations.annotations;
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

#[derive(Default)]
struct DebugAnnotations {
    annotations: Vec<idl::DebugAnnotation>,
}

macro_rules! impl_record {
    ($method:ident, $type:ty, $value_variant:ident) => {
        fn $method(&mut self, field: &Field, value: $type) {
            let mut annotation = idl::DebugAnnotation::default();
            annotation.name_field = Some(idl::debug_annotation::NameField::Name(
                field.name().to_string(),
            ));
            annotation.value = Some(idl::debug_annotation::Value::$value_variant(value.into()));
            self.annotations.push(annotation);
        }
    };
    ($method:ident, $type:ty, $value_variant:ident, $conversion:expr) => {
        fn $method(&mut self, field: &Field, value: $type) {
            let mut annotation = idl::DebugAnnotation::default();
            annotation.name_field = Some(idl::debug_annotation::NameField::Name(
                field.name().to_string(),
            ));
            annotation.value = Some(idl::debug_annotation::Value::$value_variant($conversion(
                value,
            )));
            self.annotations.push(annotation);
        }
    };
}

impl Visit for DebugAnnotations {
    impl_record!(record_bool, bool, BoolValue);
    impl_record!(record_str, &str, StringValue, String::from);
    impl_record!(record_f64, f64, DoubleValue);
    impl_record!(record_i64, i64, IntValue);
    impl_record!(record_i128, i128, StringValue, |v: i128| v.to_string());
    impl_record!(record_u128, u128, StringValue, |v: u128| v.to_string());
    impl_record!(record_u64, u64, IntValue, |v: u64| v as i64);

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let mut annotation = idl::DebugAnnotation::default();
        annotation.name_field = Some(idl::debug_annotation::NameField::Name(
            field.name().to_string(),
        ));
        annotation.value = Some(idl::debug_annotation::Value::StringValue(format!(
            "{value:?}"
        )));
        self.annotations.push(annotation);
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        let mut annotation = idl::DebugAnnotation::default();
        annotation.name_field = Some(idl::debug_annotation::NameField::Name(
            field.name().to_string(),
        ));
        annotation.value = Some(idl::debug_annotation::Value::StringValue(format!(
            "{value}"
        )));
        self.annotations.push(annotation);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;

    use tracing::{field, trace_span};
    use tracing_subscriber::{fmt::MakeWriter, layer::SubscriberExt};

    use crate::idl;
    use crate::idl::track_event;
    use crate::PerfettoLayer;
    use prost::Message;

    /// A Sink for testing that can be passed to PerfettoLayer::new to write trace data to. The
    /// sink just accumulates the trace data into a buffer in memory. The data will be
    /// `idl::Trace` protobufs which can be `.decode`'ed.
    struct TestWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl TestWriter {
        fn new() -> Self {
            Self {
                buf: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl<'a> MakeWriter<'a> for TestWriter {
        type Writer = TestWriter;
        fn make_writer(&'a self) -> Self::Writer {
            TestWriter {
                buf: self.buf.clone(),
            }
        }
    }

    impl std::io::Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buf.lock().unwrap().extend_from_slice(buf);
            std::io::Result::Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            // There's nothing to flush, we always immediately append to the buffer.
            std::io::Result::Ok(())
        }
    }

    // Check that we are able to write a span and confirm that it's written as protobuf data to the
    // output
    #[test]
    fn test_simple_span() {
        let writer = TestWriter::new();
        let extra_writer = writer.make_writer();
        let perfetto_layer = PerfettoLayer::new(writer).with_debug_annotations(true);
        let subscriber = tracing_subscriber::registry().with(perfetto_layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        {
            let demo_span = trace_span!("simple_span",);
            let _enter = demo_span.enter();
        }
        assert!(extra_writer.buf.lock().unwrap().len() > 0);
        let trace = idl::Trace::decode(extra_writer.buf.lock().unwrap().as_slice()).unwrap();

        let mut track_events_seen = 0;
        let mut saw_slice_begin = false;
        let mut saw_slice_end = false;
        // Depending on test ordering, we may or may not see a process descriptor
        for packet in trace.packet {
            let Some(idl::trace_packet::Data::TrackEvent(ref event)) = packet.data else {
                continue;
            };
            track_events_seen += 1;
            let expected = Some(track_event::NameField::Name(String::from("simple_span")));
            assert_eq!(event.name_field, expected);

            match event.r#type() {
                track_event::Type::SliceBegin => saw_slice_begin = true,
                track_event::Type::SliceEnd => saw_slice_end = true,
                _ => assert!(false, "Unexpected track event"),
            }
        }
        assert_eq!(track_events_seen, 2);
        assert!(saw_slice_begin);
        assert!(saw_slice_end);
    }

    // Check that we are able to write arguments to a span correctly
    #[test]
    fn test_span_arguments() {
        let writer = TestWriter::new();
        let extra_writer = writer.make_writer();
        let perfetto_layer = PerfettoLayer::new(writer)
            .with_debug_annotations(true)
            .with_filter_by_marker(|s| s == "regular_arg");

        let subscriber = tracing_subscriber::registry().with(perfetto_layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        {
            let demo_span = trace_span!(
                "span_with_args",
                regular_arg = "Arg data",
                extra_arg = field::Empty
            );
            let _enter = demo_span.enter();
            demo_span.record("extra_arg", "Some Extra Data");
        }
        assert!(extra_writer.buf.lock().unwrap().len() > 0);
        let trace = idl::Trace::decode(extra_writer.buf.lock().unwrap().as_slice()).unwrap();

        let mut track_events_seen = 0;
        let mut saw_slice_begin = false;
        let mut saw_slice_end = false;
        // Depending on test ordering, we may or may not see a process descriptor
        for packet in trace.packet {
            let Some(idl::trace_packet::Data::TrackEvent(ref event)) = packet.data else {
                continue;
            };
            track_events_seen += 1;
            let expected = Some(track_event::NameField::Name(String::from("span_with_args")));
            assert_eq!(event.name_field, expected);

            match event.r#type() {
                track_event::Type::SliceBegin => {
                    saw_slice_begin = true;

                    // The SliceBegin isn't recorded until it's dropped, so both the args are added to the
                    // SliceBegin record.
                    assert_eq!(event.debug_annotations.len(), 2);
                    assert_eq!(
                        event.debug_annotations[0].name_field,
                        Some(idl::debug_annotation::NameField::Name(
                            "regular_arg".to_string(),
                        ))
                    );
                    assert_eq!(
                        event.debug_annotations[0].value,
                        Some(idl::debug_annotation::Value::StringValue(
                            "Arg data".to_string(),
                        ))
                    );
                    assert_eq!(
                        event.debug_annotations[1].name_field,
                        Some(idl::debug_annotation::NameField::Name(
                            "extra_arg".to_string(),
                        ))
                    );
                    assert_eq!(
                        event.debug_annotations[1].value,
                        Some(idl::debug_annotation::Value::StringValue(
                            "Some Extra Data".to_string(),
                        ))
                    );
                }
                track_event::Type::SliceEnd => {
                    saw_slice_end = true;
                    // The SliceEnd won't have any arguments
                    assert_eq!(event.debug_annotations.len(), 0);
                }
                _ => assert!(false, "Unexpected track event"),
            }
        }
        assert_eq!(track_events_seen, 2);
        assert!(saw_slice_begin);
        assert!(saw_slice_end);
    }

    // If all our spans are filtered, we shouldn't get any trace data at all. Doing a `.record` on
    // a span should also "fail successfully".
    #[test]
    fn test_span_arguments_filtered() {
        let writer = TestWriter::new();
        let extra_writer = writer.make_writer();
        let perfetto_layer = PerfettoLayer::new(writer)
            .with_debug_annotations(true)
            .with_filter_by_marker(|s| s == "NO SUCH ARG");

        let subscriber = tracing_subscriber::registry().with(perfetto_layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        {
            let demo_span = trace_span!(
                "span_with_args",
                regular_arg = "Arg data",
                extra_arg = field::Empty
            );
            let _enter = demo_span.enter();
            demo_span.record("extra_arg", "Some Extra Data");
        }
        assert_eq!(extra_writer.buf.lock().unwrap().len(), 0);
    }
}

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]
#![forbid(unsafe_code)]

use bytes::BytesMut;
use idl_helpers::process_descriptor;
use idl_helpers::{
    create_event, create_track_descriptor, current_thread_uuid, unique_uuid, DebugAnnotations,
};
use prost::Message;
use std::io::Write;
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

mod idl_helpers;

struct PerfettoSpanState {
    track_descriptor: Option<idl::TrackDescriptor>, // optional track descriptor for this span, defaults to thread if not found
    trace: idl::Trace, // The Protobuf trace messages that we accumulate for this span.
}

/// A `Layer` that records span as perfetto's
/// `TYPE_SLICE_BEGIN`/`TYPE_SLICE_END`, and event as `TYPE_INSTANT`.
///
/// `PerfettoLayer` will output the records as encoded [protobuf messages](https://github.com/google/perfetto).
pub struct PerfettoLayer<W = fn() -> std::io::Stdout> {
    sequence_id: SequenceId,
    process_track_uuid: TrackUuid,
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
            process_track_uuid: TrackUuid::new(rand::random()),
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

    fn write_log(&self, mut log: idl::Trace, track_descriptor: idl::TrackDescriptor) {
        let mut buf = BytesMut::new();

        if let Some(p) = process_descriptor(self.process_track_uuid.get()) {
            log.packet.insert(0, p);
        }

        let mut packet = idl::TracePacket::default();
        packet.data = Some(idl::trace_packet::Data::TrackDescriptor(track_descriptor));
        log.packet.insert(1, packet);

        // if let Some(t) = track_descriptor {
        //     let mut packet = idl::TracePacket::default();
        //     packet.data = Some(idl::trace_packet::Data::TrackDescriptor(t));
        //     log.packet.insert(1, packet);
        // } else if let Some(t) = self.thread_descriptor() {
        //     log.packet.insert(1, t);
        // }

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

struct TrackNameVisitor<'a> {
    user_track_name: &'a mut Option<String>,
}

impl<'a> Visit for TrackNameVisitor<'a> {
    // fn record_u64(&mut self, field: &Field, value: u64) {
    //     if field.name() == "perfetto_track_id" {
    //         *self.user_track_id = Some(value);
    //     }
    // }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "perfetto.track_name" {
            *self.user_track_name = Some(value.to_string());
        }
    }
    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {
        // If you want to parse `perfetto_track_id` from a non-u64 typed field,
        // you could do that here, e.g. if user sets `perfetto_track_id = "0xABCD"`.
        // For now, we'll ignore it.
    }
    // Optionally implement record_* for other numeric types if needed
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

        // check if parent span has a non default track descriptor
        let inherited_track_descriptor = span
            .parent()
            // If the span has a parent, try retrieving the track descriptor from the parent's state
            .and_then(|parent_span| {
                parent_span
                    .extensions()
                    .get::<PerfettoSpanState>()
                    .map(|state| state.track_descriptor.clone())
            })
            .flatten();

        // retrieve the user set track name (via `perfetto.track_name` field)
        let mut user_track_name = None;
        let mut visitor = TrackNameVisitor {
            user_track_name: &mut user_track_name,
        };
        attrs.record(&mut visitor);

        // resolve the optional track descriptor for this span (either inherited from parent or user set, or None)
        let span_track_descriptor = user_track_name
            .map(|name| {
                let track_desc = create_track_descriptor(
                    Some(unique_uuid()),                 // uuid
                    Some(self.process_track_uuid.get()), // parent_uuid
                    Some(name),                          // name
                    None,                                // process
                    // Some(current_process_descriptor()), // process
                    // current_thread_descriptor().into(), // thread descriptor
                    None, // thread descriptor
                    None,
                );
                track_desc
            })
            .or(inherited_track_descriptor);

        let final_uuid = span_track_descriptor
            .as_ref()
            .map(|desc| desc.uuid())
            .unwrap_or_else(|| current_thread_uuid());

        let event = create_event(
            final_uuid, // span track id if exists, otherwise thread track id
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

        let span_state = PerfettoSpanState {
            track_descriptor: span_track_descriptor,
            trace: idl::Trace {
                packet: vec![packet],
            },
        };
        span.extensions_mut().insert(span_state);
    }

    fn on_record(&self, span: &span::Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(span) else {
            return;
        };

        // We don't check the filter here -- we've already checked it when we handled the span on
        // `on_new_span`. Iff we successfully attached a track packet to the span, then we'll also
        // update the trace packet with the debug data here.
        if let Some(extension) = span.extensions_mut().get_mut::<PerfettoSpanState>() {
            if let Some(idl::trace_packet::Data::TrackEvent(ref mut event)) =
                &mut extension.trace.packet[0].data
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

        let thread_track_uuid = current_thread_uuid();
        let mut track_event = create_event(
            0,
            Some(metadata.name()),
            location,
            debug_annotations,
            Some(idl::track_event::Type::Instant),
        );

        let mut packet = idl::TracePacket::default();
        // packet.data = Some(idl::trace_packet::Data::TrackEvent(track_event));
        packet.trusted_pid = Some(std::process::id() as _);
        packet.timestamp = chrono::Local::now().timestamp_nanos_opt().map(|t| t as _);
        packet.optional_trusted_packet_sequence_id = Some(
            idl::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                self.sequence_id.get() as _,
            ),
        );

        if let Some(span) = ctx.event_span(event) {
            if let Some(span_state) = span.extensions_mut().get_mut::<PerfettoSpanState>() {
                track_event.track_uuid = span_state
                    .track_descriptor
                    .as_ref()
                    .map(|d| d.uuid())
                    .or(Some(current_thread_uuid()));
                packet.data = Some(idl::trace_packet::Data::TrackEvent(track_event));
                span_state.trace.packet.push(packet);
                return;
            }
        }

        // no span or no span state, just write the event
        track_event.track_uuid = Some(thread_track_uuid);
        packet.data = Some(idl::trace_packet::Data::TrackEvent(track_event));
        let trace = idl::Trace {
            packet: vec![packet],
        };
        self.write_log(trace, idl_helpers::current_thread_track_descriptor());
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };

        let Some(mut span_state) = span.extensions_mut().remove::<PerfettoSpanState>() else {
            return;
        };

        let debug_annotations = DebugAnnotations::default();

        let track_uuid = span_state
            .track_descriptor
            .as_ref()
            .map(|d| d.uuid())
            .unwrap_or_else(|| current_thread_uuid());

        let mut packet = idl::TracePacket::default();
        let meta = span.metadata();
        let event = create_event(
            track_uuid,
            Some(meta.name()),
            meta.file().zip(meta.line()),
            debug_annotations,
            Some(idl::track_event::Type::SliceEnd),
        );
        packet.data = Some(idl::trace_packet::Data::TrackEvent(event));
        packet.timestamp = chrono::Local::now().timestamp_nanos_opt().map(|t| t as _);
        packet.trusted_pid = Some(std::process::id() as _);
        packet.optional_trusted_packet_sequence_id = Some(
            idl::trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                self.sequence_id.get() as _,
            ),
        );

        span_state.trace.packet.push(packet);

        self.write_log(
            span_state.trace,
            span_state
                .track_descriptor
                .unwrap_or_else(idl_helpers::current_thread_track_descriptor),
        );
    }
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

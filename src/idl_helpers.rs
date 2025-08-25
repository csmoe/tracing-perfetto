use crate::idl;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// This is thread safe, since duplicated descriptor will be combined into one by perfetto.
static PROCESS_DESCRIPTOR_SENT: AtomicBool = AtomicBool::new(false);
thread_local! {
    static THREAD_TRACK_UUID: AtomicU64 = AtomicU64::new(unique_uuid());
    static THREAD_DESCRIPTOR_SENT: AtomicBool = const { AtomicBool::new(false) };
}

#[derive(Default)]
pub struct DebugAnnotations {
    pub annotations: Vec<idl::DebugAnnotation>,
}

// static GLOBAL_COUNTER: AtomicU64 = AtomicU64::new(1);
pub fn unique_uuid() -> u64 {
    // generate random
    rand::random()
    // GLOBAL_COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub fn current_thread_uuid() -> u64 {
    THREAD_TRACK_UUID.with(|id| id.load(Ordering::Relaxed))
}

pub fn current_thread_descriptor() -> idl::ThreadDescriptor {
    let mut thread = idl::ThreadDescriptor::default();
    thread.pid = Some(std::process::id() as _);
    thread.tid = Some(thread_id::get() as _);
    thread.thread_name = std::thread::current().name().map(|n| n.to_string());
    thread
}

pub fn current_thread_track_descriptor() -> idl::TrackDescriptor {
    let thread_track_uuid = THREAD_TRACK_UUID.with(|id| id.load(Ordering::Relaxed));
    let thread_desc = current_thread_descriptor().into();
    let track_desc = create_track_descriptor(
        thread_track_uuid.into(),
        None,
        std::thread::current().name(),
        None,
        thread_desc,
        None,
    );
    track_desc
}

impl idl::TrackDescriptor {
    pub fn named_child_for(name: &str, parent_uuid: u64) -> Self {
        idl::TrackDescriptor {
            uuid: Some(unique_uuid()),
            parent_uuid: Some(parent_uuid),
            static_or_dynamic_name: Some(idl::track_descriptor::StaticOrDynamicName::Name(
                name.to_string(),
            )),
            ..Default::default()
        }
    }

    pub fn for_process_descriptor(uuid: u64, process_descriptor: idl::ProcessDescriptor) -> Self {
        idl::TrackDescriptor {
            uuid: Some(uuid),
            process: Some(process_descriptor),
            ..Default::default()
        }
    }
}

pub fn create_track_descriptor(
    uuid: Option<u64>,
    parent_uuid: Option<u64>,
    name: Option<impl AsRef<str>>,
    process: Option<idl::ProcessDescriptor>,
    thread: Option<idl::ThreadDescriptor>,
    counter: Option<idl::CounterDescriptor>,
) -> idl::TrackDescriptor {
    idl::TrackDescriptor {
        uuid,
        parent_uuid,
        static_or_dynamic_name: name
            .map(|s| s.as_ref().to_string())
            .map(idl::track_descriptor::StaticOrDynamicName::Name),
        process,
        thread,
        counter,
        chrome_process: None,
        chrome_thread: None,
        child_ordering: None,
        sibling_order_rank: None,
        disallow_merging_with_system_tracks: None,
    }
}

pub fn current_process_descriptor() -> idl::ProcessDescriptor {
    let mut process = idl::ProcessDescriptor::default();
    process.pid = Some(std::process::id() as _);
    process
}

pub fn process_descriptor(process_track_uuid: u64) -> Option<idl::TracePacket> {
    let process_first_frame_sent = PROCESS_DESCRIPTOR_SENT.fetch_or(true, Ordering::SeqCst);
    if process_first_frame_sent {
        return None;
    }

    let track_desc = idl::TrackDescriptor::for_process_descriptor(
        process_track_uuid,
        current_process_descriptor(),
    );

    let packet = idl::TracePacket {
        data: Some(idl::trace_packet::Data::TrackDescriptor(track_desc)),
        ..Default::default()
    };
    Some(packet)
}

pub fn create_event(
    track_uuid: u64,
    name: Option<&str>,
    location: Option<(&str, u32)>,
    debug_annotations: DebugAnnotations,
    track_event_type: Option<idl::track_event::Type>,
) -> idl::TrackEvent {
    let mut event = idl::TrackEvent {
        track_uuid: Some(track_uuid),
        categories: vec!["".to_string()],
        name_field: name.map(|name| idl::track_event::NameField::Name(name.to_string())),
        ..Default::default()
    };
    if let Some(t) = track_event_type {
        event.set_type(t);
    }

    if !debug_annotations.annotations.is_empty() {
        event.debug_annotations = debug_annotations.annotations;
    }
    if let Some((file, line)) = location {
        let source_location = idl::SourceLocation {
            file_name: Some(file.to_owned()),
            line_number: Some(line),
            ..Default::default()
        };
        let location = idl::track_event::SourceLocationField::SourceLocation(source_location);
        event.source_location_field = Some(location);
    }
    event
}

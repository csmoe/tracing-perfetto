use tracing::{info, span};
use tracing_perfetto::PerfettoLayer;
use tracing_subscriber::fmt::format::Format;
use tracing_subscriber::{fmt, layer::SubscriberExt, Registry};

fn init_subscriber() {
    let trace_path = std::env::temp_dir().join("test.pftrace");
    let trace_file = std::fs::File::create(&trace_path).unwrap();
    let perfetto_layer =
        PerfettoLayer::new(std::sync::Mutex::new(trace_file)).with_debug_annotations(true);

    let fmt_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .event_format(Format::default().with_thread_ids(true))
        .with_span_events(fmt::format::FmtSpan::FULL);

    let subscriber = Registry::default().with(fmt_layer).with(perfetto_layer);

    tracing::subscriber::set_global_default(subscriber).unwrap();
}
fn main() {
    init_subscriber();
    let main_span = span!(tracing::Level::INFO, "main");
    let _guard = main_span.enter();
    info!("start threads example with tracing");
    std::thread::sleep(std::time::Duration::from_millis(250));
    let mut join_handles = Vec::new();

    // threads with default track id
    for i in 0..3 {
        let jh = std::thread::spawn(move || {
            let _guard = span!(tracing::Level::INFO, "thread", i).entered();
            info!("thread started");
            for j in 0..3 {
                let _guard = span!(tracing::Level::INFO, "loop", i, j).entered();
                std::thread::sleep(std::time::Duration::from_millis(250));
                info!("thread inner loop");
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            info!("thread finished");
        });
        join_handles.push(jh);
    }

    for i in 0..3 {
        let jh = std::thread::spawn(move || {
            let _guard = span!(
                tracing::Level::INFO,
                "thread",
                i,
                perfetto.track_name = format!("thread track {}", i)
            )
            .entered();
            info!("thread started");
            for j in 0..3 {
                let _guard = span!(tracing::Level::INFO, "loop", i, j).entered();
                std::thread::sleep(std::time::Duration::from_millis(250));
                info!("thread inner loop");
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            info!("thread finished");
        });

        join_handles.push(jh);
    }

    for jh in join_handles {
        jh.join().unwrap();
    }
    info!("end threads example with tracing");
    std::thread::sleep(std::time::Duration::from_millis(250));
}

//! Thread-local capture of emitted `tracing` events for async tests.
//!
//! Async-safe: uses `dispatcher::set_default` (a `DefaultGuard` held across the
//! awaited call), not the sync `with_default` closure. A permissive global
//! default is installed once so the `warn!` is not short-circuited by the
//! runtime max-level hint before the scoped dispatcher runs.
#![expect(clippy::unwrap_used, reason = "tests")]

use std::fmt::Write as _;
use std::sync::{Arc, Mutex, Once};

use tracing::Subscriber;
use tracing::dispatcher::DefaultGuard;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::Registry;

static PERMISSIVE_GLOBAL: Once = Once::new();

fn ensure_permissive_global() {
    PERMISSIVE_GLOBAL.call_once(|| {
        // A no-op global whose max_level_hint is unbounded, so WARN events are
        // not filtered before the scoped dispatcher sees them. Ignore the error
        // if some other component already set a global default.
        let _ = tracing::subscriber::set_global_default(Registry::default());
    });
}

struct CaptureLayer {
    events: Arc<Mutex<Vec<String>>>,
}

struct FieldWriter<'a>(&'a mut String);
impl Visit for FieldWriter<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        write!(self.0, " {}={value:?}", field.name()).ok();
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        write!(self.0, " {}={value}", field.name()).ok();
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        write!(self.0, " {}={value}", field.name()).ok();
    }
}

impl<S: Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut record = format!("target={}", event.metadata().target());
        event.record(&mut FieldWriter(&mut record));
        self.events.lock().unwrap().push(record);
    }
}

/// A scoped capture. Hold it across the awaited call under test; read
/// `records` afterward. Dropping it removes the thread-local dispatcher.
pub struct WarnCapture {
    _guard: DefaultGuard,
    events: Arc<Mutex<Vec<String>>>,
}

impl WarnCapture {
    /// Install a thread-local capturing dispatcher on the current thread.
    /// Hold the returned guard across the awaited call under test.
    #[must_use]
    pub fn install() -> WarnCapture {
        ensure_permissive_global();
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let layer = CaptureLayer {
            events: Arc::clone(&events),
        };
        let dispatch = tracing::Dispatch::new(Registry::default().with(layer));
        let guard = tracing::dispatcher::set_default(&dispatch);
        WarnCapture {
            _guard: guard,
            events,
        }
    }

    /// Snapshot of captured `"target=... field=value ..."` records.
    #[must_use]
    pub fn records(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

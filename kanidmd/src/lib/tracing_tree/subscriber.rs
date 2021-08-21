use std::any::TypeId;
use std::convert::TryFrom;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::Future;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tracing::dispatcher::SetGlobalDefaultError;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Record};
use tracing::{Event, Id, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layered, SubscriberExt};
use tracing_subscriber::registry::{LookupSpan, Registry, Scope, SpanRef};
use tracing_subscriber::Layer;
use uuid::Uuid;

use crate::tracing_tree::processor::TestProcessor;

use super::formatter::LogFmt;
use super::processor::{ExportProcessor, Processor};
use super::timings::Timer;
use super::EventTag;

pub struct TreeSubscriber<P> {
    inner: Layered<TreeLayer<P>, Registry>,
}

struct TreeLayer<P> {
    fmt: LogFmt,
    processor: P,
}

#[derive(Debug)]
pub(crate) struct TreeEvent {
    pub timestamp: DateTime<Utc>,
    pub message: String,
    pub level: Level,
    pub tag: Option<EventTag>,
    pub values: Vec<(&'static str, String)>,
}

#[derive(Debug)]
struct TreeSpan {
    pub timestamp: DateTime<Utc>,
    pub name: &'static str,
    pub buf: Vec<Tree>,
    pub uuid: Option<String>,
    pub out: TreeIo,
}

#[derive(Debug)]
enum Tree {
    Event(TreeEvent),
    Span(TreeSpan, Duration),
}

#[derive(Debug)]
pub struct TreePreProcessed {
    fmt: LogFmt,
    logs: Tree,
}

#[derive(Debug)]
pub enum TreeIo {
    Stdout,
    Stderr,
    File(PathBuf),
}

pub(crate) struct TreeSpanProcessed {
    pub timestamp: DateTime<Utc>,
    pub name: &'static str,
    pub processed_buf: Vec<TreeProcessed>,
    pub uuid: Option<String>,
    pub out: TreeIo,
    pub nested_duration: u64,
    pub total_duration: u64,
}

pub(crate) enum TreeProcessed {
    Event(TreeEvent),
    Span(TreeSpanProcessed),
}

impl TreeSubscriber<ExportProcessor> {
    fn new_with(fmt: LogFmt, sender: UnboundedSender<TreePreProcessed>) -> Self {
        let layer = TreeLayer {
            fmt,
            processor: ExportProcessor::with_sender(sender),
        };

        TreeSubscriber {
            inner: Registry::default().with(layer),
        }
    }

    pub fn new(fmt: LogFmt) -> (Self, impl Future<Output = ()>) {
        let (log_tx, mut log_rx) = unbounded_channel();
        let subscriber = TreeSubscriber::new_with(fmt, log_tx);
        let logger = async move {
            while let Some(processor) = log_rx.recv().await {
                #[allow(clippy::expect_used)]
                processor.process().expect("Failed to write logs");
            }
        };

        (subscriber, logger)
    }

    // These are the preferred constructors.
    #[allow(dead_code)]
    pub fn json() -> (Self, impl Future<Output = ()>) {
        TreeSubscriber::new(LogFmt::Json)
    }

    #[allow(dead_code)]
    pub fn pretty() -> (Self, impl Future<Output = ()>) {
        TreeSubscriber::new(LogFmt::Pretty)
    }
}

impl<P: Processor> TreeSubscriber<P> {
    #[allow(dead_code)]
    pub fn thread_operation_id(&self) -> Option<Uuid> {
        let current = self.inner.current_span();
        // If there's no current span, we short-circuit.
        let id = current.id()?;
        #[allow(clippy::expect_used)]
        let span = self
            .inner
            .span(id)
            .expect("The subscriber doesn't have data for an existing span, this is a bug");

        span.scope().into_iter().find_map(|span| {
            let extensions = span.extensions();
            // If `uuid` is `None`, then we keep searching.
            #[allow(clippy::expect_used)]
            let uuid = extensions
                .get::<TreeSpan>()
                .expect("Span buffer not found, this is a bug")
                .uuid
                .as_ref()?;
            // TODO: make spans store UUID's as a u128 or 2 u64's
            #[allow(clippy::expect_used)]
            Some(Uuid::parse_str(uuid.as_str()).expect("Unable to parse UUID, this is a bug"))
        })
    }
}

impl<P: Processor> Subscriber for TreeSubscriber<P> {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        self.inner.max_level_hint()
    }

    fn new_span(&self, span: &Attributes) -> Id {
        self.inner.new_span(span)
    }

    fn record(&self, span: &Id, values: &Record) {
        self.inner.record(span, values)
    }

    fn record_follows_from(&self, span: &Id, follows: &Id) {
        self.inner.record_follows_from(span, follows)
    }

    fn event(&self, event: &Event) {
        self.inner.event(event)
    }

    fn enter(&self, span: &Id) {
        self.inner.enter(span)
    }

    fn exit(&self, span: &Id) {
        self.inner.exit(span)
    }

    fn clone_span(&self, id: &Id) -> Id {
        self.inner.clone_span(id)
    }

    fn try_close(&self, id: Id) -> bool {
        self.inner.try_close(id)
    }

    unsafe fn downcast_raw(&self, id: TypeId) -> Option<*const ()> {
        // Allows us to access this or nested subscribers from dispatch
        if id == TypeId::of::<Self>() {
            Some(self as *const Self as *const ())
        } else {
            self.inner.downcast_raw(id)
        }
    }
}

impl<P: Processor> TreeLayer<P> {
    fn log_to_parent(&self, logs: Tree, parent: Option<SpanRef<Registry>>) {
        match parent {
            // The parent exists- write to them
            #[allow(clippy::expect_used)]
            Some(span) => span
                .extensions_mut()
                .get_mut::<TreeSpan>()
                .expect("Log buffer not found, this is a bug")
                .log(logs),
            // The parent doesn't exist- send to formatter
            None => self.processor.process(TreePreProcessed {
                fmt: self.fmt,
                logs,
            }),
        }
    }
}

impl<P: Processor> Layer<Registry> for TreeLayer<P> {
    fn new_span(&self, attrs: &Attributes, id: &Id, ctx: Context<Registry>) {
        #[allow(clippy::expect_used)]
        let span = ctx.span(id).expect("Span not found, this is a bug");

        let name = attrs.metadata().name();
        let mut uuid = None;
        let mut out = TreeIo::Stderr;

        attrs.record(
            &mut |field: &Field, value: &dyn fmt::Debug| match field.name() {
                "uuid" => {
                    uuid = Some(format!("{:?}", value));
                }
                "output" if ctx.lookup_current().is_none() => {
                    out = match format!("{:?}", value).as_str() {
                        "console stdout" => TreeIo::Stdout,
                        "console stderr" => TreeIo::Stderr,
                        path => TreeIo::File(PathBuf::from(path)),
                    };
                }
                _ => {}
            },
        );

        // Take provided ID, or make a fresh one if there's no parent span.
        let uuid = uuid.or_else(|| {
            ctx.lookup_current()
                .is_none()
                .then(|| Uuid::new_v4().to_string())
        });

        let mut extensions = span.extensions_mut();

        extensions.insert(TreeSpan::new(name, uuid, out));
        extensions.insert(Timer::new());
    }

    fn on_event(&self, event: &Event, ctx: Context<Registry>) {
        let (tree_event, immediate) = TreeEvent::parse(event);

        if immediate {
            use super::formatter::format_immediate_event;
            let maybe_scope = ctx.event_scope(event).map(Scope::from_root);
            #[allow(clippy::expect_used)]
            let formatted_event = format_immediate_event(&tree_event, maybe_scope)
                .expect("Formatting immediate event failed");
            eprintln!("{}", formatted_event);
        }

        self.log_to_parent(Tree::Event(tree_event), ctx.event_span(event));
    }

    fn on_enter(&self, id: &Id, ctx: Context<Registry>) {
        #[allow(clippy::expect_used)]
        ctx.span(id)
            .expect("Span not found, this is a bug")
            .extensions_mut()
            .get_mut::<Timer>()
            .expect("Timer not found, this is a bug")
            .unpause();
    }

    fn on_exit(&self, id: &Id, ctx: Context<Registry>) {
        #[allow(clippy::expect_used)]
        ctx.span(id)
            .expect("Span not found, this is a bug")
            .extensions_mut()
            .get_mut::<Timer>()
            .expect("Timer not found, this is a bug")
            .pause();
    }

    fn on_close(&self, id: Id, ctx: Context<Registry>) {
        #[allow(clippy::expect_used)]
        let span = ctx.span(&id).expect("Span not found, this is a bug");

        let mut extensions = span.extensions_mut();

        #[allow(clippy::expect_used)]
        let span_buf = extensions
            .remove::<TreeSpan>()
            .expect("Span buffer not found, this is a bug");

        #[allow(clippy::expect_used)]
        let duration = extensions
            .remove::<Timer>()
            .expect("Timer not found, this is a bug")
            .duration();

        let logs = Tree::Span(span_buf, duration);

        self.log_to_parent(logs, span.parent());
    }
}

impl TreeEvent {
    fn parse(event: &Event) -> (Self, bool) {
        let timestamp = Utc::now();
        let level = *event.metadata().level();

        struct Visitor {
            message: String,
            tag: Option<EventTag>,
            values: Vec<(&'static str, String)>,
            immediate: bool,
        }

        impl Visit for Visitor {
            fn record_u64(&mut self, field: &Field, value: u64) {
                if field.name() == "event_tag_id" {
                    let tag = EventTag::try_from(value).unwrap_or_else(|_| {
                        panic!("Invalid `event_tag_id`: {}, this is a bug", value)
                    });
                    self.tag = Some(tag);
                } else {
                    self.record_debug(field, &value)
                }
            }

            fn record_bool(&mut self, field: &Field, value: bool) {
                if field.name() == "immediate" {
                    self.immediate = value;
                } else {
                    self.record_debug(field, &value)
                }
            }

            fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
                if field.name() == "message" {
                    use fmt::Write;
                    #[allow(clippy::expect_used)]
                    write!(self.message, "{:?}", value).expect("Write failed");
                } else {
                    self.values.push((field.name(), format!("{:?}", value)));
                }
            }
        }

        let mut v = Visitor {
            message: String::new(),
            tag: None,
            values: vec![],
            immediate: false,
        };

        event.record(&mut v);

        let Visitor {
            message,
            tag,
            values,
            immediate,
        } = v;

        (
            TreeEvent {
                timestamp,
                message,
                level,
                tag,
                values,
            },
            immediate,
        )
    }

    pub(super) fn emoji(&self) -> &'static str {
        self.tag
            .map(EventTag::emoji)
            .unwrap_or_else(|| match self.level {
                Level::ERROR => "🚨",
                Level::WARN => "🚧",
                Level::INFO => "💬",
                Level::DEBUG => "🐛",
                Level::TRACE => "📍",
            })
    }

    pub(super) fn tag(&self) -> &'static str {
        self.tag
            .map(EventTag::pretty)
            .unwrap_or_else(|| match self.level {
                Level::ERROR => "error",
                Level::WARN => "warn",
                Level::INFO => "info",
                Level::DEBUG => "debug",
                Level::TRACE => "trace",
            })
    }
}

impl TreeSpan {
    fn new(name: &'static str, uuid: Option<String>, out: TreeIo) -> Self {
        TreeSpan {
            timestamp: Utc::now(),
            name,
            buf: vec![],
            uuid,
            out,
        }
    }

    fn log(&mut self, logs: Tree) {
        self.buf.push(logs)
    }
}

impl Tree {
    pub fn process(self) -> TreeProcessed {
        match self {
            Tree::Event(event) => TreeProcessed::Event(event),
            Tree::Span(span_buf, duration) => {
                let mut processed_buf = vec![];

                let nested_duration = span_buf
                    .buf
                    .into_iter()
                    .map(|logs| {
                        let processed = logs.process();

                        let duration = match processed {
                            TreeProcessed::Span(ref span) => span.total_duration,
                            _ => 0,
                        };

                        // Side effect: Push processed logs to processed_buf
                        processed_buf.push(processed);

                        duration
                    })
                    .sum::<u64>();

                TreeProcessed::Span(TreeSpanProcessed {
                    timestamp: span_buf.timestamp,
                    name: span_buf.name,
                    processed_buf,
                    uuid: span_buf.uuid,
                    out: span_buf.out,
                    nested_duration,
                    total_duration: duration.as_nanos() as u64,
                })
            }
        }
    }
}

impl TreePreProcessed {
    pub fn process(self) -> io::Result<()> {
        let processed_logs = self.logs.process();
        let formatted_logs = self.fmt.format(&processed_logs);

        let buf = &formatted_logs[..];

        match processed_logs.tree_io() {
            TreeIo::Stdout => io::stdout().write_all(buf),
            TreeIo::Stderr => io::stderr().write_all(buf),
            TreeIo::File(ref path) => OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open(path)?
                .write_all(buf),
        }
    }
}

impl TreeProcessed {
    fn tree_io(self) -> TreeIo {
        match self {
            TreeProcessed::Event(_) => TreeIo::Stderr,
            TreeProcessed::Span(TreeSpanProcessed { out, .. }) => out,
        }
    }
}

// Returns the UUID of the threads current span operation, or None if not in any spans.
#[allow(dead_code)]
pub fn operation_id() -> Option<Uuid> {
    tracing::dispatcher::get_default(|dispatch| {
        // Try to find the release subscriber
        #[allow(clippy::expect_used)]
        dispatch
            .downcast_ref::<TreeSubscriber<ExportProcessor>>()
            .map(TreeSubscriber::<ExportProcessor>::thread_operation_id)
            .or_else(|| {
                // Try to find the testing subscriber
                dispatch
                    .downcast_ref::<TreeSubscriber<TestProcessor>>()
                    .map(TreeSubscriber::<TestProcessor>::thread_operation_id)
            })
            .expect("operation_id only works for `TreeSubscriber`'s!")
    })
}

pub fn main_init() -> JoinHandle<()> {
    let (subscriber, logger) = TreeSubscriber::pretty();
    #[allow(clippy::expect_used)]
    tracing::subscriber::set_global_default(subscriber)
        .expect("🚨🚨🚨 Global subscriber already set, this is a bug 🚨🚨🚨");
    tokio::spawn(logger)
}

// This should be used in testing only, because it processes logs on the working thread.
// The main benefit is that this makes testing much easier, since it can be called in
// every test without worring about a processing thread in a test holding an `UnboundedReceiver`
// and then getting dropped, making the global subscriber panic on further attempts to send logs.
#[allow(dead_code)]
pub fn test_init() -> Result<(), SetGlobalDefaultError> {
    tracing::subscriber::set_global_default(TreeSubscriber {
        inner: Registry::default().with(TreeLayer {
            fmt: LogFmt::Pretty,
            processor: TestProcessor {},
        }),
    })
}

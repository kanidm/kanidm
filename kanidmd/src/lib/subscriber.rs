use tracing::{
    span::{Attributes, Record},
    Event, Id, Metadata, Subscriber,
};
use tracing_subscriber::{
    layer::{Context, Layered, SubscriberExt as _},
    registry::Registry,
    Layer,
};

pub struct KaniSubscriber {
    inner: Layered<KaniLayer, Registry>,
}

pub struct KaniLayer;

// This could be a DST since it gets boxed internally.
// Feel like that might be overengineering things a bit though.
// Also everything about this type is very temporary.
pub struct KaniLogBuffer {
    path: String, // the string containing the spans it's wrapped in?
    // this is poorly designed but hopefully works
    buf: Vec<String>,
}

impl Layer<Registry> for KaniLayer {
    fn new_span(&self, attrs: &Attributes, id: &Id, ctx: Context<Registry>) {
        ctx.span(id)
            .expect("the span doesn't exist even though we just made it??")
            .extensions_mut()
            .insert(KaniLogBuffer::new(/* ctx stuff here */));

        let _ = attrs;
    }

    fn on_event(&self, event: &Event, ctx: Context<Registry>) {
        // How can I make it so that this wraps one of `tracing_subscriber`s
        // preexisting formatting utilities?
        // I don't want to do the formatting by myself ;(
        let span = match ctx.lookup_current() {
            Some(span) => span,
            _ => {
                // We're not in any spans, do we still care about the log?
                // Let's just ignore it for now and short-circuit.
                return;
            }
        };

        // `extensions_mut` returns an `ExtensionsMut`, which is essentially a
        // wrapping for the `AnyMap` type offered in https://docs.rs/anymap/0.12.1/anymap/
        let mut ext_mut = span.extensions_mut();

        let logbuf = ext_mut
            .get_mut::<KaniLogBuffer>()
            .expect("doesn't have a logbuf even though we initialized one?");

        // TODO: use some formatter to transform this event into a nice string
        let event_string = format!("{:?}", event);

        logbuf.log(event_string);
    }

    fn on_exit(&self, id: &Id, ctx: Context<Registry>) {
        let span = ctx.span(id).expect("how is the span not in ctx?");

        let mut ext_mut = span.extensions_mut();

        let logs = ext_mut
            // We can take the `KaniLogBuffer` here because we're done with it
            .remove::<KaniLogBuffer>()
            .expect("doesn't have a logbuf even though we initialized one?")
            .dump();

        match span.parent() {
            Some(parent) => {
                // There exists a parent span
                // Write to parent
                let mut ext_mut = parent.extensions_mut();

                ext_mut
                    .get_mut::<KaniLogBuffer>()
                    .expect("has to be here")
                    .log(logs);
            }
            None => {
                // There is no parent span
                // Write to `stderr`
                eprintln!("{}", logs);
            }
        }
    }
}

impl KaniLogBuffer {
    pub fn new() -> Self {
        let mut logbuf = KaniLogBuffer {
            // TODO: use ctx to get information about what this should be
            path: "a path".to_string(),
            buf: vec![],
        };
        // TODO: update this to use the ctx to get span information
        logbuf.log(format!("INFO: {}: OPENED", logbuf.path));
        logbuf
    }

    pub fn log(&mut self, event: String) {
        self.buf.push(event)
    }

    pub fn dump(mut self) -> String {
        // TODO: update this to use the ctx to get span information
        self.log(format!("INFO: {}: CLOSED", self.path));
        self.buf.join("\n")
    }
}

impl KaniSubscriber {
    pub fn new() -> Self {
        println!("OOGA NEW SUBSCRIBER");
        KaniSubscriber {
            inner: Registry::default().with(KaniLayer),
        }
    }
}

impl Subscriber for KaniSubscriber {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.inner.enabled(metadata)
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
}

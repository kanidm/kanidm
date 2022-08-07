#[macro_export]
macro_rules! spanned {
    ($name:expr, $code:block) => {{
        // Block: can short circuit outer function
        use tracing::trace_span;
        let _entered_span = trace_span!($name).entered();
        $code
    }};
    ($name:expr, || $code:block) => {{
        // Closure: cannot short circuit outer function
        use tracing::trace_span;
        let _entered_span = trace_span!($name).entered();
        (|| $code)()
    }};
}

#[macro_export]
macro_rules! tagged_event {
    ($level:ident, $event_tag:path, $($arg:tt)*) => {{
        use tracing;
        fn assert_eventtag(_: &EventTag) {}
        assert_eventtag(&$event_tag);
        let event_tag_id: u64 = $event_tag.into();
        tracing::event!(tracing::Level::$level, event_tag_id, $($arg)*)
    }}
}

#[macro_export]
macro_rules! admin_debug {
    ($($arg:tt)*) => { tagged_event!(DEBUG, EventTag::AdminDebug, $($arg)*) }
}

#[macro_export]
macro_rules! admin_error {
    ($($arg:tt)*) => { tagged_event!(ERROR, EventTag::AdminError, $($arg)*) }
}

#[macro_export]
macro_rules! admin_warn {
    ($($arg:tt)*) => { tagged_event!(WARN, EventTag::AdminWarn, $($arg)*) }
}

#[macro_export]
macro_rules! admin_info {
    ($($arg:tt)*) => { tagged_event!(INFO, EventTag::AdminInfo, $($arg)*) }
}

#[macro_export]
macro_rules! request_error {
    ($($arg:tt)*) => { tagged_event!(ERROR, EventTag::RequestError, $($arg)*) }
}

#[macro_export]
macro_rules! request_warn {
    ($($arg:tt)*) => { tagged_event!(WARN, EventTag::RequestWarn, $($arg)*) }
}

#[macro_export]
macro_rules! request_info {
    ($($arg:tt)*) => { tagged_event!(INFO, EventTag::RequestInfo, $($arg)*) }
}

#[macro_export]
macro_rules! request_trace {
    ($($arg:tt)*) => { tagged_event!(TRACE, EventTag::RequestTrace, $($arg)*) }
}

#[macro_export]
macro_rules! security_critical {
    ($($arg:tt)*) => { tagged_event!(INFO, EventTag::SecurityCritical, $($arg)*) }
}

#[macro_export]
macro_rules! security_error {
    ($($arg:tt)*) => { tagged_event!(ERROR, EventTag::SecurityError, $($arg)*) }
}

#[macro_export]
macro_rules! security_info {
    ($($arg:tt)*) => { tagged_event!(INFO, EventTag::SecurityInfo, $($arg)*) }
}

#[macro_export]
macro_rules! security_access {
    ($($arg:tt)*) => { tagged_event!(INFO, EventTag::SecurityAccess, $($arg)*) }
}

#[macro_export]
macro_rules! filter_error {
    ($($arg:tt)*) => { tagged_event!(ERROR, EventTag::FilterError, $($arg)*) }
}

#[macro_export]
macro_rules! filter_warn {
    ($($arg:tt)*) => { tagged_event!(WARN, EventTag::FilterWarn, $($arg)*) }
}

#[macro_export]
macro_rules! filter_info {
    ($($arg:tt)*) => { tagged_event!(INFO, EventTag::FilterInfo, $($arg)*) }
}

#[macro_export]
macro_rules! filter_trace {
    ($($arg:tt)*) => { tagged_event!(TRACE, EventTag::FilterTrace, $($arg)*) }
}

#[macro_export]
macro_rules! perf_trace {
    ($($arg:tt)*) => { tagged_event!(TRACE, EventTag::PerfTrace, $($arg)*) }
}

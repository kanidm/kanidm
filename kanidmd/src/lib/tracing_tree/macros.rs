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
        fn assert_eventtag(_: &crate::tracing_tree::EventTag) {}
        assert_eventtag(&$event_tag);
        let event_tag_id: u64 = $event_tag.into();
        tracing::event!(tracing::Level::$level, event_tag_id, $($arg)*)
    }}
}

#[macro_export]
macro_rules! admin_error {
    ($($arg:tt)*) => { crate::tagged_event!(ERROR, crate::tracing_tree::EventTag::AdminError, $($arg)*) }
}

#[macro_export]
macro_rules! admin_warn {
    ($($arg:tt)*) => { crate::tagged_event!(WARN, crate::tracing_tree::EventTag::AdminWarn, $($arg)*) }
}

#[macro_export]
macro_rules! admin_info {
    ($($arg:tt)*) => { crate::tagged_event!(INFO, crate::tracing_tree::EventTag::AdminInfo, $($arg)*) }
}

#[macro_export]
macro_rules! request_error {
    ($($arg:tt)*) => { crate::tagged_event!(ERROR, crate::tracing_tree::EventTag::RequestError, $($arg)*) }
}

#[macro_export]
macro_rules! request_warn {
    ($($arg:tt)*) => { crate::tagged_event!(WARN, crate::tracing_tree::EventTag::RequestWarn, $($arg)*) }
}

#[macro_export]
macro_rules! request_info {
    ($($arg:tt)*) => { crate::tagged_event!(INFO, crate::tracing_tree::EventTag::RequestInfo, $($arg)*) }
}

#[macro_export]
macro_rules! request_trace {
    ($($arg:tt)*) => { crate::tagged_event!(TRACE, crate::tracing_tree::EventTag::RequestTrace, $($arg)*) }
}

#[macro_export]
macro_rules! security_critical {
    ($($arg:tt)*) => { crate::tagged_event!(INFO, crate::tracing_tree::EventTag::SecurityCritical, $($arg)*) }
}

#[macro_export]
macro_rules! security_info {
    ($($arg:tt)*) => { crate::tagged_event!(INFO, crate::tracing_tree::EventTag::SecurityInfo, $($arg)*) }
}

#[macro_export]
macro_rules! security_access {
    ($($arg:tt)*) => { crate::tagged_event!(INFO, crate::tracing_tree::EventTag::SecurityAccess, $($arg)*) }
}

#[macro_export]
macro_rules! filter_error {
    ($($arg:tt)*) => { crate::tagged_event!(ERROR, crate::tracing_tree::EventTag::FilterError, $($arg)*) }
}

#[macro_export]
macro_rules! filter_warn {
    ($($arg:tt)*) => { crate::tagged_event!(WARN, crate::tracing_tree::EventTag::FilterWarn, $($arg)*) }
}

#[macro_export]
macro_rules! filter_info {
    ($($arg:tt)*) => { crate::tagged_event!(INFO, crate::tracing_tree::EventTag::FilterInfo, $($arg)*) }
}

#[macro_export]
macro_rules! filter_trace {
    ($($arg:tt)*) => { crate::tagged_event!(TRACE, crate::tracing_tree::EventTag::FilterTrace, $($arg)*) }
}

#[macro_export]
macro_rules! perf_trace {
    ($($arg:tt)*) => { crate::tagged_event!(TRACE, crate::tracing_tree::EventTag::PerfTrace, $($arg)*) }
}

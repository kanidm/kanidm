#[macro_export]
macro_rules! alarm {
    ($($arg:tt)*) => {{
        use tracing;
        tracing::error!(alarm = true, $($arg)*);
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! tagged_event {
    ($level:ident, $logtag:path, $($arg:tt)*) => {{
        use tracing;
        fn assert_eventtagset<T: crate::tracing_tree::EventTagSet>(_x: &T) {}
        assert_eventtagset(&$logtag);
        let event_tag: u64 = $logtag.into();
        tracing::event!(tracing::Level::$level, event_tag, $($arg)*)
    }}
}

#[macro_export]
macro_rules! admin_error {
    ($($arg:tt)*) => { crate::tagged_event!(ERROR, crate::tracing_tree::event_tag::KanidmEventTag::AdminError, $($arg)*) }
}

#[macro_export]
macro_rules! admin_warn {
    ($($arg:tt)*) => { crate::tagged_event!(WARN, crate::tracing_tree::event_tag::KanidmEventTag::AdminWarn, $($arg)*) }
}

#[macro_export]
macro_rules! admin_info {
    ($($arg:tt)*) => { crate::tagged_event!(INFO, crate::tracing_tree::event_tag::KanidmEventTag::AdminInfo, $($arg)*) }
}

#[macro_export]
macro_rules! request_error {
    ($($arg:tt)*) => { crate::tagged_event!(ERROR, crate::tracing_tree::event_tag::KanidmEventTag::RequestError, $($arg)*) }
}

#[macro_export]
macro_rules! request_warn {
    ($($arg:tt)*) => { crate::tagged_event!(WARN, crate::tracing_tree::event_tag::KanidmEventTag::RequestWarn, $($arg)*) }
}

#[macro_export]
macro_rules! request_info {
    ($($arg:tt)*) => { crate::tagged_event!(INFO, crate::tracing_tree::event_tag::KanidmEventTag::RequestInfo, $($arg)*) }
}

#[macro_export]
macro_rules! request_trace {
    ($($arg:tt)*) => { crate::tagged_event!(TRACE, crate::tracing_tree::event_tag::KanidmEventTag::RequestTrace, $($arg)*) }
}

#[macro_export]
macro_rules! security_critical {
    ($($arg:tt)*) => { crate::tagged_event!(INFO, crate::tracing_tree::event_tag::KanidmEventTag::SecurityCritical, $($arg)*) }
}

#[macro_export]
macro_rules! security_info {
    ($($arg:tt)*) => { crate::tagged_event!(INFO, crate::tracing_tree::event_tag::KanidmEventTag::SecurityInfo, $($arg)*) }
}

#[macro_export]
macro_rules! security_access {
    ($($arg:tt)*) => { crate::tagged_event!(INFO, crate::tracing_tree::event_tag::KanidmEventTag::SecurityAccess, $($arg)*) }
}

#[macro_export]
macro_rules! filter_error {
    ($($arg:tt)*) => { crate::tagged_event!(ERROR, crate::tracing_tree::event_tag::KanidmEventTag::FilterError, $($arg)*) }
}

#[macro_export]
macro_rules! filter_warn {
    ($($arg:tt)*) => { crate::tagged_event!(WARN, crate::tracing_tree::event_tag::KanidmEventTag::FilterWarn, $($arg)*) }
}

#[macro_export]
macro_rules! filter_info {
    ($($arg:tt)*) => { crate::tagged_event!(INFO, crate::tracing_tree::event_tag::KanidmEventTag::FilterInfo, $($arg)*) }
}

#[macro_export]
macro_rules! filter_trace {
    ($($arg:tt)*) => { crate::tagged_event!(TRACE, crate::tracing_tree::event_tag::KanidmEventTag::FilterTrace, $($arg)*) }
}

#[macro_export]
macro_rules! perf_trace {
    ($($arg:tt)*) => { crate::tagged_event!(TRACE, crate::tracing_tree::event_tag::KanidmEventTag::PerfTrace, $($arg)*) }
}

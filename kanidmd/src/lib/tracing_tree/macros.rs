#[macro_export]
macro_rules! spanned {
    /* BLOCK: can short circuit outer function */
    // Inherit log level of parent
    ($name:literal, $code:block) => {{
        crate::spanned!(::tracing::Level::TRACE, $name, $code)
    }};
    // Dynamically specify a log level
    ($lvl:expr, $name:literal, $code:block) => {{
        let _entered_span = ::tracing::span!($lvl, $name).entered();
        $code
    }};
    /* CLOSURE: cannot short circuit outer function */
    // Inherit log level of parent
    ($name:literal, || $code:block) => {{
        crate::spanned!(::tracing::Level::TRACE, $name, || $code)
    }};
    // Dynamically specify a log level
    ($lvl:expr, $name:literal, || $code:block) => {{
        let _entered_span = ::tracing::span!($lvl, $name).entered();
        (|| $code)()
    }};
}

#[macro_export]
macro_rules! trace_spanned {
    ($name:literal, $code:block) => {{
        crate::spanned!(::tracing::Level::TRACE, $name, $code)
    }};
    ($name:literal, || $code:block) => {{
        crate::spanned!(::tracing::Level::TRACE, $name, || $code)
    }};
}

#[macro_export]
macro_rules! debug_spanned {
    ($name:literal, $code:block) => {{
        crate::spanned!(::tracing::Level::DEBUG, $name, $code)
    }};
    ($name:literal, || $code:block) => {{
        crate::spanned!(::tracing::Level::DEBUG, $name, || $code)
    }};
}

#[macro_export]
macro_rules! info_spanned {
    ($name:literal, $code:block) => {{
        crate::spanned!(::tracing::Level::INFO, $name, $code)
    }};
    ($name:literal, || $code:block) => {{
        crate::spanned!(::tracing::Level::INFO, $name, || $code)
    }};
}

#[macro_export]
macro_rules! warn_spanned {
    ($name:literal, $code:block) => {{
        crate::spanned!(::tracing::Level::WARN, $name, $code)
    }};
    ($name:literal, || $code:block) => {{
        crate::spanned!(::tracing::Level::WARN, $name, || $code)
    }};
}

#[macro_export]
macro_rules! error_spanned {
    ($name:literal, $code:block) => {{
        crate::spanned!(::tracing::Level::ERROR, $name, $code)
    }};
    ($name:literal, || $code:block) => {{
        crate::spanned!(::tracing::Level::ERROR, $name, || $code)
    }};
}

#[macro_export]
macro_rules! tagged_event {
    ($level:ident, $event_tag:path, $($arg:tt)*) => {{
        fn assert_eventtag(_: &crate::tracing_tree::EventTag) {}
        assert_eventtag(&$event_tag);
        let event_tag_id: u64 = $event_tag.into();
        ::tracing::event!(::tracing::Level::$level, event_tag_id, $($arg)*)
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
macro_rules! security_error {
    ($($arg:tt)*) => { crate::tagged_event!(ERROR, crate::tracing_tree::EventTag::SecurityError, $($arg)*) }
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

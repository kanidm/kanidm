/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef FR_LOG_H
#define FR_LOG_H
/**
 * $Id: f978496a0a32bcadd89f5465675a80058fb8f923 $
 *
 * @file log.h
 * @brief Macros and function definitions to write log messages, and control the logging system.
 *
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(log_h, "$Id: f978496a0a32bcadd89f5465675a80058fb8f923 $")

#ifdef __cplusplus
extern "C" {
#endif

typedef enum log_type {
	L_AUTH = 2,		//!< Authentication message.
	L_INFO = 3,		//!< Informational message.
	L_ERR = 4,		//!< Error message.
	L_WARN = 5,		//!< Warning.
	L_PROXY	= 6,		//!< Proxy messages
	L_ACCT = 7,		//!< Accounting messages

	L_DBG = 16,		//!< Only displayed when debugging is enabled.
	L_DBG_WARN = 17,	//!< Warning only displayed when debugging is enabled.
	L_DBG_ERR = 18,		//!< Error only displayed when debugging is enabled.
	L_DBG_WARN_REQ = 19,	//!< Less severe warning only displayed when debugging is enabled.
	L_DBG_ERR_REQ = 20	//!< Less severe error only displayed when debugging is enabled.
} log_type_t;

typedef enum log_lvl {
	L_DBG_LVL_DISABLE = -1,	//!< Don't print messages.
	L_DBG_LVL_OFF = 0,	//!< No debug messages.
	L_DBG_LVL_1,		//!< Highest priority debug messages (-x).
	L_DBG_LVL_2,		//!< 2nd highest priority debug messages (-xx | -X).
	L_DBG_LVL_3,		//!< 3rd highest priority debug messages (-xxx | -Xx).
	L_DBG_LVL_MAX		//!< Lowest priority debug messages (-xxxx | -Xxx).
} log_lvl_t;

typedef enum log_dst {
	L_DST_STDOUT = 0,	//!< Log to stdout.
	L_DST_FILES,		//!< Log to a file on disk.
	L_DST_SYSLOG,		//!< Log to syslog.
	L_DST_STDERR,		//!< Log to stderr.
	L_DST_NULL,		//!< Discard log messages.
	L_DST_NUM_DEST
} log_dst_t;

typedef struct fr_log_t {
	bool		colourise;	//!< Prefix log messages with VT100 escape codes to change text
					//!< colour.
	int		fd;		//!< File descriptor to write messages to.
	log_dst_t	dst;		//!< Log destination.
	char const	*file;		//!< Path to log file.
	char const	*debug_file;	//!< Path to debug log file.
	bool		timestamp;	//!< Should logs always have timestamps.
} fr_log_t;

typedef		void (*radlog_func_t)(log_type_t lvl, log_lvl_t priority, REQUEST *, char const *, va_list ap);

extern FR_NAME_NUMBER const syslog_facility_table[];
extern FR_NAME_NUMBER const syslog_severity_table[];
extern FR_NAME_NUMBER const log_str2dst[];
extern fr_log_t default_log;

int	radlog_init(fr_log_t *log, bool daemonize);

int	vradlog(log_type_t lvl, char const *fmt, va_list ap)
	CC_HINT(format (printf, 2, 0)) CC_HINT(nonnull);
int	radlog(log_type_t lvl, char const *fmt, ...)
	CC_HINT(format (printf, 2, 3)) CC_HINT(nonnull (2));

bool	debug_enabled(log_type_t type, log_lvl_t lvl);

bool	rate_limit_enabled(void);

bool	radlog_debug_enabled(log_type_t type, log_lvl_t lvl, REQUEST *request)
	CC_HINT(nonnull);

void	vradlog_request(log_type_t type, log_lvl_t lvl, REQUEST *request, char const *msg, va_list ap)
	CC_HINT(format (printf, 4, 0)) CC_HINT(nonnull (3, 4));

void	radlog_request(log_type_t type, log_lvl_t lvl, REQUEST *request, char const *msg, ...)
	CC_HINT(format (printf, 4, 5)) CC_HINT(nonnull (3, 4));

void	radlog_request_error(log_type_t type, log_lvl_t lvl, REQUEST *request, char const *msg, ...)
	CC_HINT(format (printf, 4, 5)) CC_HINT(nonnull (3, 4));

void	radlog_request_marker(log_type_t type, log_lvl_t lvl, REQUEST *request,
			      char const *fmt, size_t indent, char const *error)
	CC_HINT(nonnull);

void	fr_canonicalize_error(TALLOC_CTX *ctx, char **spaces, char **text, ssize_t slen, char const *msg);

/** @name Log global messages
 *
 * Write to the global log.
 *
 * Messages will always be written irrespective of the debugging level set with ``-x`` or ``-X``.
 *
 * @warning If a REQUEST * is **NOT** available, these macros **MUST** be used.
 *
 * @note These macros should only be used for important global events.
 *
 * **Debug categories**
 * Name     | Syslog severity         | Colour/style | When to use
 * -------- | ----------------------- | ------------ | -----------
 * AUTH     | LOG_NOTICE              | Bold         | Never - Deprecated
 * ACCT     | LOG_NOTICE              | Bold         | Never - Deprecated
 * PROXY    | LOG_NOTICE              | Bold         | Never - Deprecated
 * INFO     | LOG_INFO                | Bold         | TBD
 * WARN     | LOG_WARNING             | Yellow       | Warnings. Impending resource exhaustion, resource exhaustion
 * ERROR    | LOG_ERR                 | Red          | Critical server errors. Malformed queries, failed operations, connection errors, packet processing errors
 *
 * @{
 */
#define AUTH(fmt, ...)		radlog(L_AUTH, fmt, ## __VA_ARGS__)
#define ACCT(fmt, ...)		radlog(L_ACCT, fmt, ## __VA_ARGS__)
#define PROXY(fmt, ...)		radlog(L_PROXY, fmt, ## __VA_ARGS__)

#define INFO(fmt, ...)		radlog(L_INFO,  fmt, ## __VA_ARGS__)
#define WARN(fmt, ...)		radlog(L_WARN, fmt, ## __VA_ARGS__)
#define ERROR(fmt, ...)		radlog(L_ERR, fmt, ## __VA_ARGS__)
/** @} */

/** @name Log global debug messages (DEBUG*)
 *
 * Write debugging messages to the global log.
 *
 * Messages will be written if the debug level is high enough.
 *
 * **Debug categories**
 * Name     | Syslog severity         | Colour/style | When to use
 * -------- | ----------------------- | -------------| -----------
 * DEBUG    | LOG_DEBUG               | Regular      | Normal debug output
 *
 * **Debug levels**
 * Level    | Debug arguments         | Macro(s) enabled              | When to use
 * -------- | ----------------------- | ----------------------------- | -----------
 * 1        | ``-x``                  | DEBUG                         | Never - Deprecated
 * 2        | ``-xx`` or ``-X``       | DEBUG, DEBUG2                 | Interactions with external entities. Connection management, control socket, triggers, etc...
 * 3        | ``-xxx`` or ``-Xx``     | DEBUG, DEBUG2, DEBUG3         | Lower priority events. Polling for detail files, cleanups, etc...
 * 4        | ``-xxxx`` or ``-Xxx``   | DEBUG, DEBUG2, DEBUG3, DEBUG4 | Internal server state debugging.
 *
 * @{
 */
#define DEBUG_ENABLED		debug_enabled(L_DBG, L_DBG_LVL_1)			//!< True if global debug level 1 messages are enabled
#define DEBUG_ENABLED2		debug_enabled(L_DBG, L_DBG_LVL_2)			//!< True if global debug level 1-2 messages are enabled
#define DEBUG_ENABLED3		debug_enabled(L_DBG, L_DBG_LVL_3)			//!< True if global debug level 1-3 messages are enabled
#define DEBUG_ENABLED4		debug_enabled(L_DBG, L_DBG_LVL_MAX)			//!< True if global debug level 1-4 messages are enabled

#define _SL(_l, _p, _f, ...)	if (rad_debug_lvl >= _p) radlog(_l, _f, ## __VA_ARGS__)
#define DEBUG(fmt, ...)		_SL(L_DBG, L_DBG_LVL_1, fmt, ## __VA_ARGS__)
#define DEBUG2(fmt, ...)	_SL(L_DBG, L_DBG_LVL_2, fmt, ## __VA_ARGS__)
#define DEBUG3(fmt, ...)	_SL(L_DBG, L_DBG_LVL_3, fmt, ## __VA_ARGS__)
#define DEBUG4(fmt, ...)	_SL(L_DBG, L_DBG_LVL_MAX, fmt, ## __VA_ARGS__)
/** @} */

/** @name Log request-specific messages (R*)
 *
 * Write to the request log, or the global log if a request logging function is not set.
 *
 * Messages will always be written irrespective of the debugging level set with ``-x`` or ``-X``.
 *
 * @note Automatically prepends date (at lvl >= 3), request number, and module, to the log message.
 * @note If a REQUEST * is available, these macros should be used.
 * @note These macros should only be used for important global events.
 *
 * **Debug categories**
 * Name     | Syslog severity         | Colour/style | When to use
 * -------- | ----------------------- | -------------| -----------
 * RAUTH    | LOG_NOTICE              | Bold         | Never - Deprecated
 * RACCT    | LOG_NOTICE              | Bold         | Never - Deprecated
 * RPROXY   | LOG_NOTICE              | Bold         | Never - Deprecated
 * RINFO    | LOG_INFO                | Bold         | TBD
 * RWARN    | LOG_WARNING             | Yellow/Bold  | Warnings. Impending resource exhaustion, or resource exhaustion.
 * RERROR   | LOG_ERR                 | Red/Bold     | Critical server errors. Malformed queries, failed operations, connection errors, packet processing errors.
 * @{
 */
#define RAUTH(fmt, ...)		radlog_request(L_AUTH, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
#define RACCT(fmt, ...)		radlog_request(L_ACCT, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
#define RPROXY(fmt, ...)	radlog_request(L_PROXY, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
#define RINFO(fmt, ...)		radlog_request(L_INFO, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
#define RWARN(fmt, ...)		radlog_request(L_DBG_WARN, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
#define RERROR(fmt, ...)	radlog_request_error(L_DBG_ERR, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
/** @} */

/** @name Log request-specific debug (R*DEBUG*)
 *
 * Write debug messages to the request log.
 *
 * Messages will only be written if a request log function is set and the request or global
 * debug level is high enough.
 *
 * @note Automatically prepends date (at lvl >= 3), request number, and module, to the log message.
 *
 * **Debug categories**
 * Name     | Syslog severity         | Colour and style | When to use
 * -------- | ----------------------- | -----------------| -----------
 * RDEBUG*  | LOG_DEBUG               | Regular          | Normal debugging messages
 * RIDEBUG* | LOG_DEBUG               | Bold             | Informational messages.
 * RWDEBUG* | LOG_DEBUG               | Yellow/Bold      | Warnings. Invalid configuration, missing or invalid attributes etc...
 * REDEBUG* | LOG_DEBUG               | Red/Bold         | Errors. Reject messages, bad values etc...
 *
 * **Debug levels**
 * Level    | Debug arguments         | Macro(s) enabled                       | When to use
 * -------- | ----------------------- | -------------------------------------- | -----------
 * 1        | ``-x``                  | R*DEBUG                                | Never - Deprecated
 * 2        | ``-xx`` or ``-X``       | R*DEBUG, R*DEBUG2                      | Normal request flow. Operations, Results of queries, or execs, etc...
 * 3        | ``-xxx`` or ``-Xx``     | R*DEBUG, R*DEBUG2, R*DEBUG3            | Internal server state or packet input. State machine changes, extra attribute info, etc...
 * 4        | ``-xxxx`` or ``-Xxx``   | R*DEBUG, R*DEBUG2, R*DEBUG3, R*DEBUG4  | Verbose internal server state messages or packet input. Hex dumps, structure dumps, pointer values.
 *
 * @{
 */
#define RDEBUG_ENABLED		radlog_debug_enabled(L_DBG, L_DBG_LVL_1, request)	//!< True if request debug level 1 messages are enabled
#define RDEBUG_ENABLED2		radlog_debug_enabled(L_DBG, L_DBG_LVL_2, request)	//!< True if request debug level 1-2 messages are enabled
#define RDEBUG_ENABLED3		radlog_debug_enabled(L_DBG, L_DBG_LVL_3, request)	//!< True if request debug level 1-3 messages are enabled
#define RDEBUG_ENABLED4		radlog_debug_enabled(L_DBG, L_DBG_LVL_MAX, request)	//!< True if request debug level 1-4 messages are enabled

#define RDEBUGX(_l, fmt, ...)	radlog_request(L_DBG, _l, request, fmt, ## __VA_ARGS__)
#define RDEBUG(fmt, ...)	if (rad_debug_lvl || request->log.lvl) radlog_request(L_DBG, L_DBG_LVL_1, request, fmt, ## __VA_ARGS__)
#define RDEBUG2(fmt, ...)	if (rad_debug_lvl || request->log.lvl) radlog_request(L_DBG, L_DBG_LVL_2, request, fmt, ## __VA_ARGS__)
#define RDEBUG3(fmt, ...)	if (rad_debug_lvl || request->log.lvl) radlog_request(L_DBG, L_DBG_LVL_3, request, fmt, ## __VA_ARGS__)
#define RDEBUG4(fmt, ...)	if (rad_debug_lvl || request->log.lvl) radlog_request(L_DBG, L_DBG_LVL_MAX, request, fmt, ## __VA_ARGS__)

#define RIDEBUG(fmt, ...)	radlog_request(L_INFO, L_DBG_LVL_1, request, fmt, ## __VA_ARGS__)
#define RIDEBUG2(fmt, ...)	radlog_request(L_INFO, L_DBG_LVL_2, request, fmt, ## __VA_ARGS__)

#define RWDEBUG(fmt, ...)	if (rad_debug_lvl || request->log.lvl) radlog_request(L_DBG_WARN, L_DBG_LVL_1, request, fmt, ## __VA_ARGS__)
#define RWDEBUG2(fmt, ...)	if (rad_debug_lvl || request->log.lvl) radlog_request(L_DBG_WARN, L_DBG_LVL_2, request, fmt, ## __VA_ARGS__)

#define REDEBUG(fmt, ...)	radlog_request_error(L_DBG_ERR, L_DBG_LVL_1, request, fmt, ## __VA_ARGS__)
#define REDEBUG2(fmt, ...)	radlog_request_error(L_DBG_ERR, L_DBG_LVL_2, request, fmt, ## __VA_ARGS__)
#define REDEBUG3(fmt, ...)	radlog_request_error(L_DBG_ERR, L_DBG_LVL_3, request, fmt, ## __VA_ARGS__)
#define REDEBUG4(fmt, ...)	radlog_request_error(L_DBG_ERR, L_DBG_LVL_MAX, request, fmt, ## __VA_ARGS__)
/** @} */

/** Indent R* messages by one level
 *
 * @note Has no effect on the indentation of INFO, WARN, ERROR, DEBUG messages,
 *	 only RINFO, RWARN, RERROR etc...
 */
#define RINDENT() (request->log.indent += 2)

/** Exdent (unindent) R* messages by one level
 *
 * @note Has no effect on the indentation of INFO, WARN, ERROR, DEBUG messages,
 *	 only RINFO, RWARN, RERROR etc...
 */
#define REXDENT() (request->log.indent -= 2)

/** Output string with error marker, showing where format error occurred
 *
 @verbatim
   my pet kitty
      ^ kitties are not pets, are nature devouring hell beasts
 @endverbatim
 *
 * @warning If a REQUEST * is **NOT** available, or is NULL, this macro must **NOT** be used.
 *
 * @param _l log category, a log_type_t value.
 * @param _p log priority, a log_lvl_t value.
 * @param _m string to mark e.g. "my pet kitty".
 * @param _i index e.g. 3 (starts from 0).
 * @param _e error e.g. "kitties are not pets, are nature devouring hell beasts".
 */
#define RMARKER(_l, _p, _m, _i, _e)	radlog_request_marker(_l, _p, request, _m, _i, _e)

/** Output string with error marker, showing where format error occurred
 *
 * These are logged as RERROR messages.
 *
 @verbatim
   my pet kitty
      ^ kitties are not pets, are nature devouring hell beasts
 @endverbatim
 *
 * @warning If a REQUEST * is **NOT** available, or is NULL, this macro must **NOT** be used.
 *
 * @param _m string to mark e.g. "my pet kitty".
 * @param _i index e.g. 3 (starts from 0).
 * @param _e error e.g. "kitties are not pets, are nature devouring hell beasts".
 */
#define REMARKER(_m, _i, _e)		RMARKER(L_DBG_ERR, L_DBG_LVL_1, _m, _i, _e)

/** Output string with error marker, showing where format error occurred
 *
 * These are logged as RDEBUG messages.
 *
 @verbatim
   my pet kitty
      ^ kitties are not pets, are nature devouring hell beasts
 @endverbatim
 *
 * @warning If a REQUEST * is **NOT** available, or is NULL, this macro must **NOT** be used.
 *
 * @param _m string to mark e.g. "my pet kitty".
 * @param _i index e.g. 3 (starts from 0).
 * @param _e error e.g. "kitties are not pets, are nature devouring hell beasts".
 */
#define RDMARKER(_m, _i, _e)		RMARKER(L_DBG, L_DBG_LVL_1, _m, _i, _e)

/** Use different logging functions depending on whether request is NULL or not.
 *
 * @note The module must define MOD_PREFIX as its name (do this in the module
 *	 header file) e.g. @code{.c}#define MOD_PREFIX "rlm_example"@endcode
 *
 * This is useful for areas of code which are run on server startup, and when
 * processing requests.
 *
 * @param _l_request The name of a R* logging macro e.g. RDEBUG3.
 * @param _l_global The name of a global logging macro e.g. DEBUG3.
 * @param fmt printf style format string.
 * @param ... printf arguments.
 */
 #define MOD_ROPTIONAL(_l_request, _l_global, fmt, ...) \
do {\
	if (request) {\
		_l_request(fmt, ## __VA_ARGS__);\
	} else {\
		_l_global(MOD_PREFIX " (%s): " fmt, inst->name, ## __VA_ARGS__);\
 	}\
} while (0)

/** Use different logging functions depending on whether request is NULL or not.
 *
 * This is useful for areas of code which are run on server startup, and when
 * processing requests.
 *
 * @param _l_request The name of a R* logging macro e.g. RDEBUG3.
 * @param _l_global The name of a global logging macro e.g. DEBUG3.
 * @param fmt printf style format string.
 * @param ... printf arguments.
 */
 #define ROPTIONAL(_l_request, _l_global, fmt, ...) \
do {\
	if (request) {\
		_l_request(fmt, ## __VA_ARGS__);\
	} else {\
		_l_global(LOG_PREFIX ": " fmt, ## __VA_ARGS__);\
 	}\
} while (0)

#define RATE_LIMIT_ENABLED rate_limit_enabled()		//!< True if rate limiting is enabled.
/** Rate limit messages
 *
 * Rate limit log messages so they're written a maximum of once per second.
 *
 @code{.c}
   RATE_LIMIT(RERROR("Home servers alive in pool %s", pool->name));
 @endcode
 * @note Rate limits the macro, not the message. If five different messages are
 *	 produced using the same macro in the same second, only the first will
 *	 be written to the log.
 *
 * @param _x Logging macro to limit.
 */
#define RATE_LIMIT(_x) \
do {\
	if (RATE_LIMIT_ENABLED) {\
		static time_t _last_complained = 0;\
		time_t _now = time(NULL);\
		if (_now != _last_complained) {\
			_last_complained = _now;\
			_x;\
		}\
	} else _x;\
} while (0)

#ifdef __cplusplus
}
#endif

#endif /* FR_LOG_H */

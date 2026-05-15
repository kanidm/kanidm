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
#ifndef LISTEN_H
#define LISTEN_H
/**
 * $Id: 1d952272946bf835720c7e4f947c68af848695c4 $
 *
 * @file listen.h
 * @brief The listener API.
 *
 * @copyright 2015  The FreeRADIUS server project
 */

/*
 *	Types of listeners.
 *
 *	Ordered by priority!
 */
typedef enum RAD_LISTEN_TYPE {
	RAD_LISTEN_NONE = 0,
	RAD_LISTEN_PROXY,
	RAD_LISTEN_AUTH,
	RAD_LISTEN_ACCT,
	RAD_LISTEN_DETAIL,
	RAD_LISTEN_VQP,
	RAD_LISTEN_DHCP,
	RAD_LISTEN_COMMAND,
	RAD_LISTEN_COA,
	RAD_LISTEN_MAX
} RAD_LISTEN_TYPE;

typedef enum RAD_LISTEN_STATUS {
	RAD_LISTEN_STATUS_INIT = 0,		//!< starting up
	RAD_LISTEN_STATUS_KNOWN,		//!< alive and operating normally
	RAD_LISTEN_STATUS_PAUSE,		//!< TLS connection checking: don't read normal packets
	RAD_LISTEN_STATUS_RESUME,		//!< TLS connection checking: resume reading normal packets
	RAD_LISTEN_STATUS_FROZEN,		//!< alive, but we're not sending any more packets to it
	RAD_LISTEN_STATUS_EOL,			//!< we're trying to delete it.
	RAD_LISTEN_STATUS_REMOVE_NOW		//!< no request is using it, delete the listener.
} RAD_LISTEN_STATUS;

typedef struct rad_listen rad_listen_t;

typedef int (*rad_listen_recv_t)(rad_listen_t *);
typedef int (*rad_listen_send_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_print_t)(rad_listen_t const *, char *, size_t);
typedef int (*rad_listen_encode_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_decode_t)(rad_listen_t *, REQUEST *);

struct rad_listen {
	rad_listen_t *next; /* should be rbtree stuff */

	/*
	 *	For normal sockets.
	 */
	RAD_LISTEN_TYPE	type;
	int		fd;
	char const	*server;
	int		status;
	int		count;
#ifdef WITH_TCP
	rbtree_t	*children;
	rad_listen_t	*parent;

	bool		dual;
	bool		proxy_protocol;		//!< haproxy protocol
	bool		listen;			//! just calls listen()
#endif
	bool		nodup;
	bool		dead;

#ifdef WITH_TLS
	fr_tls_server_conf_t *tls;
	bool		check_client_connections;
	bool		nonblock;
	bool		blocked;
#ifdef WITH_RADIUSV11
	fr_radiusv11_t 	radiusv11;
#endif

#ifdef WITH_COA_TUNNEL
	char const	*key;		/* Originating-Realm-Key */
	bool		send_coa;	/* to the NAS */

	uint32_t	coa_irt;
	uint32_t	coa_mrc;
	uint32_t	coa_mrt;
	uint32_t	coa_mrd;

	int		num_ids_used;	/* for proxying CoA packets */
#endif
#endif

	rad_listen_recv_t recv;
	rad_listen_send_t send;

	/*
	 *	We don't need a proxy_recv, because the main loop in
	 *	process.c calls listener->recv(), and we don't know
	 *	what kind of packet we're receiving until we receive
	 *	it.
	 */
	rad_listen_send_t proxy_send;


	rad_listen_encode_t encode;
	rad_listen_decode_t decode;
	rad_listen_encode_t proxy_encode;
	rad_listen_decode_t proxy_decode;
	rad_listen_print_t print;

	CONF_SECTION const *cs;
	void		*data;

#ifdef WITH_STATS
	fr_stats_t	stats;
#endif
};

/*
 *	This shouldn't really be exposed...
 */
typedef struct listen_socket_t {
	/*
	 *	For normal sockets.
	 */
	fr_ipaddr_t	my_ipaddr;
	uint16_t	my_port;

	uint32_t	backlog;

	char const	*interface;
#ifdef SO_BROADCAST
	int		broadcast;
#endif

	int		recv_buff;

	time_t		rate_time;
	uint32_t	rate_pps_old;
	uint32_t	rate_pps_now;
	uint32_t	max_rate;

	/* for outgoing sockets */
	home_server_t	*home;
	fr_ipaddr_t	other_ipaddr;
	uint16_t	other_port;

	int		proto;

#ifdef WITH_TCP
	/* for a proxy connecting to home servers */
	time_t		last_packet;
	time_t		opened;
	fr_event_t	*ev;

	fr_socket_limit_t limit;

	struct listen_socket_t *parent;
	RADCLIENT	*client;

	RADIUS_PACKET   *packet; /* for reading partial packets */

	fr_ipaddr_t	haproxy_src_ipaddr;	//!< for proxy_protocol
	fr_ipaddr_t	haproxy_dst_ipaddr;
	uint16_t	haproxy_src_port;
	uint16_t	haproxy_dst_port;
#endif

#ifdef WITH_TLS
	tls_session_t	*ssn;
	REQUEST		*request; /* horrible hacks */
	VALUE_PAIR	*certs;
	uint32_t	connect_timeout;
	pthread_mutex_t mutex;
	uint8_t		*data;
	size_t		partial;

	fr_event_fd_handler_t write_handler;
	enum {
		LISTEN_TLS_INIT = 0,
		LISTEN_TLS_CHECKING,
		LISTEN_TLS_SETUP,
		LISTEN_TLS_RUNNING,
	} state;

	bool		client_closed;

#ifdef WITH_RADIUSV11
	bool		alpn_checked;
	bool		radiusv11;		//!< defaults to "no"!
#endif
#endif

	RADCLIENT_LIST	*clients;
} listen_socket_t;
#endif /* LISTEN_H */


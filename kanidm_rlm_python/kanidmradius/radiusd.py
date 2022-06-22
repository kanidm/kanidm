""" this was pulled from freeradius """
#!/usr/bin/python3
#
# Definitions for RADIUS programs
#
# Copyright 2002 Miguel A.L. Paraz <mparaz@mparaz.com>
#
# This should only be used when testing modules.
# Inside freeradius, the 'radiusd' Python module is created by the C module
# and the definitions are automatically created.
#
# $Id: e9db28a4fa7dc8fe163a1d1a1dcf23771ef32990 $

# from modules.h

RLM_MODULE_REJECT = 0
RLM_MODULE_FAIL = 1
RLM_MODULE_OK = 2
RLM_MODULE_HANDLED = 3
RLM_MODULE_INVALID = 4
RLM_MODULE_USERLOCK = 5
RLM_MODULE_NOTFOUND = 6
RLM_MODULE_NOOP = 7
RLM_MODULE_UPDATED = 8
RLM_MODULE_NUMCODES = 9

# from log.h
L_AUTH = 2
L_INFO = 3
L_ERR = 4
L_WARN = 5
L_PROXY = 6
L_ACCT = 7

L_DBG = 16
L_DBG_WARN = 17
L_DBG_ERR = 18
L_DBG_WARN_REQ = 19
L_DBG_ERR_REQ = 20

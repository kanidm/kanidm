""" kanidm client exceptions """

class AuthBeginFailed(Exception):
    """ Auth Failed at the begin step """

class AuthCredFailed(Exception):
    """ Auth Failed at the init step """

class AuthInitFailed(Exception):
    """ Auth Failed at the init step """

class AuthMechUnknown(Exception):
    """ Not sure what mech was passed but it wasn't the one we wanted """

class ServerURLNotSet(Exception):
    """ You haven't set the URL for the server! """

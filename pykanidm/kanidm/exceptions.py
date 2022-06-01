""" kanidm client exceptions """

class AuthCredFailed(Exception):
    """ Auth Failed at the init step """

class AuthInitFailed(Exception):
    """ Auth Failed at the init step """

class AuthMechUnknown(Exception):
    """ Auth Failed at the init step """

class ServerURLNotSet(Exception):
    """ You haven't set the URL for the server! """

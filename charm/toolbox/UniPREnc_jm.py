''' Base class for Proxy Re-Encryption

 Notes: This class implements an interface for a standard proxy re-encryption scheme.

 A proxy re-encryption scheme consists of eight algorithms:
 (setup, keygen, encrypt_lvl1, encrypt_lvl2, decrypt_lvl1, decrypt_lvl2, re_keygen, re_encrypt).
'''
from charm.toolbox.schemebase import *


class UniPREnc(SchemeBase):
    def __init__(self):
        SchemeBase.__init__(self)
        SchemeBase._setProperty(self, scheme='PREnc')
        # self.baseSecDefs = Enum('IND_AB_CPA', 'IND_AB_CCA', 'sIND_AB_CPA', 'sIND_AB_CCA')

    def setup(self):
        raise NotImplementedError

    def keygen(self, params, **kwargs):
        raise NotImplementedError

    def encrypt_lvl1(self, params, pk, m, **kwargs):
        raise NotImplementedError

    def encrypt_lvl2(self, params, pk, m, **kwargs):
        raise NotImplementedError

    def decrypt_lvl1(self, params, sk, c, **kwargs):
        raise NotImplementedError

    def decrypt_lvl2(self, params, sk, c, **kwargs):
        raise NotImplementedError

    def re_keygen(self, params, sk, pk, **kwargs):
        raise NotImplementedError

    def re_encrypt(self, params, rk, c, **kwargs):
        raise NotImplementedError


class MissingRequiredKeywordArgumentError(Exception):
    def __init__(self, keywords=None):
        if keywords is None or type(keywords) != list or len(keywords) == 0:
            'Missing required keyword arguments: N/A'
        if len(keywords) == 1:
            message = 'Missing required keyword argument: ' + keywords[0] + '.'
        else:
            message = 'Missing required keyword arguments: ' + ", ".join(keywords) + '.'
        super().__init__(message)

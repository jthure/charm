"""
LV11 - Proxy re-encryption.
| From: B. Libert and D. Vergnaud. (2011). Unidirectional Chosen-Ciphertext Secure Proxy Re-Encryption
| Published in: IEEE Transactions on Information Theory
* type:         proxy encryption
* properties:   RCCA-secure, unidirectional, single-Hop, collusion resistant, non-transistive, non-interactive.
* setting:      Pairing groups (Type 1 "symmetric")
* assumption:   eDBDH (Extended Decisional Bilinear DH)
:Authors:   M. Örndahl & J. Thuresson
:Date:      03/2018
"""
# noinspection PyUnresolvedReferences
from charm.toolbox.pairinggroup import ZR, G1, GT, pair

from charm.toolbox.UniPREnc_jm import MissingRequiredKeywordArgumentError
from charm.schemes.prenc.pre_lv11_jm import LV11


class LV11Temp(LV11):
    """
    Testing LV11 Temnporary implementation
    >>> from charm.toolbox.pairinggroup import PairingGroup
    >>> from charm.schemes.pksig.lamport_jm import Lamport
    >>> groupObj = PairingGroup('SS512')
    >>> sigObj = Lamport()
    >>> pre = LV11Temp(groupObj, sigObj)
    >>> params = pre.setup()
    >>> (pk_a, sk_a) = pre.keygen(params)
    >>> (pk_b, sk_b) = pre.keygen(params)
    >>> msg = groupObj.random(GT)
    >>> c_a_1_2018 = pre.encrypt_lvl1(params, pk_a, msg, l='2018')
    >>> c_a_2_2018 = pre.encrypt_lvl2(params, pk_a, msg, l='2018')
    >>> rk_2018 = pre.re_keygen(params, pk_b, sk_a, l='2018', pk_a=pk_a)
    >>> rk_2017 = pre.re_keygen(params, pk_b, sk_a, l='2017', pk_a=pk_a)
    >>> c_b_1_2018 = pre.re_encrypt(params, rk_2018, c_a_2_2018, l='2018', pk_a=pk_a)
    >>> c_b_1_2017 = pre.re_encrypt(params, rk_2017, c_a_2_2018, l='2018', pk_a=pk_a)
    >>> dec_ca1 = pre.decrypt_lvl1(params, sk_a, c_a_1_2018, pk_b=pk_a)
    >>> assert msg == dec_ca1, 'Decryption of level 1 ciphertext was incorrect'
    >>> dec_cb = pre.decrypt_lvl1(params, sk_b, c_b_1_2018, pk_b=pk_b)
    >>> assert msg == dec_cb, 'Decryption of level 1 re-encrypted ciphertext was incorrect'
    >>> dec_cb_2 = pre.decrypt_lvl1(params, sk_b, c_b_1_2017, pk_b=pk_b)
    >>> assert dec_cb_2 is None, 'Decryption of wrongle re-encrypted ciphertext didnt yield None'
    >>> dec_ca2 = pre.decrypt_lvl2(params, sk_a, c_a_2_2018, pk_a=pk_a)
    >>> assert msg == dec_ca2, 'Decryption of level 2 ciphertext was incorrect'
    """

    @staticmethod
    def _F_i(params, pk, l):
        pk_2 = pk['pk2']
        F_i = (params['g'] ** l) * pk_2
        return F_i

    def _verify_sig(self, params, C):
        l, C0, C3, C4, sigma = C['l'], C['C0'], C['C3'], C['C4'], C['sigma']
        return params['sig'].verify(C0, (self.group.serialize(l) + self.group.serialize(C3) + self.group.serialize(C4)),
                                    sigma)

    def keygen(self, params, **kwargs):
        g_x1, x1 = super().keygen(params, **kwargs)
        x2 = self.group.random(ZR)
        g_x2 = params['g'] ** x2
        if self.pre_compute:
            g_x2.initPP()
        sk = {'sk1': x1, 'sk2': x2}
        pk = {'pk1': g_x1, 'pk2': g_x2}
        return pk, sk

    def re_keygen(self, params, pk_b, sk_a, **kwargs):
        if 'l' not in kwargs or 'pk_a' not in kwargs: raise MissingRequiredKeywordArgumentError(['pk_a', 'l'])
        l, pk_a = kwargs['l'], kwargs['pk_a']
        pk_b_1 = pk_b['pk1']
        pk_a_1 = pk_a['pk1']
        sk_a_1 = sk_a['sk1']
        r = self.group.random(ZR)
        l = self.group.hash(l)
        F_i = self._F_i(params, pk_a, l)
        rk_1 = (pk_b_1 ** (1 / sk_a_1)) * (F_i ** r)
        rk_2 = pk_a_1 ** r
        if self.pre_compute:
            rk_1.initPP()
            rk_2.initPP()
        return rk_1, rk_2

    def encrypt_lvl1(self, params, pk_a, m, **kwargs):
        if 'l' not in kwargs: raise MissingRequiredKeywordArgumentError(['l'])
        l = kwargs['l']
        (svk, ssk) = params['sig'].keygen()
        pk_a_1 = pk_a['pk1']
        s, t1, t2 = self.group.random(ZR, 3)
        l = self.group.hash(l)
        g = params['g']
        F_i = self._F_i(params, pk_a, l)

        C0 = svk
        C1_1 = pk_a_1 ** t1
        C1_2 = (F_i * g) ** (1 / t1)
        C1_3 = pk_a_1 ** (s * t1)
        C2_1 = F_i ** t2
        C2_2 = pk_a_1 ** (1 / t2)
        C2_3 = F_i ** (s * t2)
        C3 = (pair(params['g'], params['g']) ** s) * m
        C4 = ((params['u'] ** self.group.hash(svk)) * params['v']) ** s

        sigma = params['sig'].sign(svk, ssk,
                                   self.group.serialize(l) + self.group.serialize(C3) + self.group.serialize(C4))

        C = {'l': l, 'C0': C0, 'C1_1': C1_1, 'C1_2': C1_2, 'C1_3': C1_3, 'C2_1': C2_1, 'C2_2': C2_2, 'C2_3': C2_3,
             'C3': C3, 'C4': C4, 'sigma': sigma}
        return C

    def encrypt_lvl2(self, params, pk_a, m, **kwargs):
        if 'l' not in kwargs: raise MissingRequiredKeywordArgumentError(['l'])
        l = kwargs['l']
        (svk, ssk) = params['sig'].keygen()
        pk_a_1 = pk_a['pk1']
        s = self.group.random(ZR)
        l = self.group.hash(l)
        F_i = self._F_i(params, pk_a, l)
        g = params['g']

        C0 = svk
        C1 = pk_a_1 ** s
        C2 = F_i ** s
        C3 = (pair(g, g) ** s) * m
        C4 = ((params['u'] ** self.group.hash(svk)) * params['v']) ** s

        sigma = params['sig'].sign(svk, ssk, self.group.serialize(l) + self.group.serialize(C3) +
                                   self.group.serialize(C4))

        C = {'l': l, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4, 'sigma': sigma}
        return C

    def re_encrypt(self, params, rk_ab, C_a, **kwargs):
        if 'l' not in kwargs or 'pk_a' not in kwargs: raise MissingRequiredKeywordArgumentError(['l', 'pk_a'])
        l, pk_a = kwargs['l'], kwargs['pk_a']
        pk_a_1 = pk_a['pk1']
        l, C0, C1, C2, C3, C4, sigma = C_a['l'], C_a['C0'], C_a['C1'], C_a['C2'], C_a['C3'], C_a['C4'], C_a['sigma']
        if not self._verify_sig(params, C_a):
            return None
        F_i = self._F_i(params, pk_a, l)
        if pair(pk_a_1, C2) != pair(C1, F_i):
            return None
        if pair(pk_a_1, C4) != pair(C1, (params['u'] ** self.group.hash(C0)) * params['v']):
            return None

        t1, t2 = self.group.random(ZR, 2)
        rk_a, rk_b = rk_ab

        C1_1 = pk_a_1 ** t1
        C1_2 = rk_a ** (1 / t1)
        C1_3 = C1 ** t1
        C2_1 = F_i ** t2
        C2_2 = rk_b ** (1 / t2)
        C2_3 = C2 ** t2

        C = {'l': l, 'C0': C0, 'C1_1': C1_1, 'C1_2': C1_2, 'C1_3': C1_3, 'C2_1': C2_1, 'C2_2': C2_2, 'C2_3': C2_3,
             'C3': C3, 'C4': C4, 'sigma': sigma}
        return C

    def decrypt_lvl1(self, params, sk_b, C_b, **kwargs):
        if 'pk_b' not in kwargs: raise MissingRequiredKeywordArgumentError(['pk_b'])
        pk_b = kwargs['pk_b']
        l, C0, C1_1, C1_2, C1_3, C2_1, C2_2, C2_3, C3, C4, sigma = C_b['l'], C_b['C0'], C_b['C1_1'], C_b['C1_2'], \
                                                                   C_b['C1_3'], C_b['C2_1'], C_b['C2_2'], C_b['C2_3'], \
                                                                   C_b['C3'], C_b['C4'], C_b['sigma']
        pk_b_1 = pk_b['pk1']
        sk_b_1 = sk_b['sk1']

        temp = params['u'] ** self.group.hash(C0) * params['v']
        if not self._verify_sig(params, C_b):
            return None
        if pair(C1_1, C4) != pair(C1_3, temp):
            return None
        if pair(C2_1, C4) != pair(C2_3, temp):
            return None
        if pair(C1_1, C1_2) != pair(pk_b_1, params['g']) * pair(C2_1, C2_2):
            return None
        m = C3 * (pair(C2_2, C2_3) / pair(C1_2, C1_3)) ** (1 / sk_b_1)
        return m

    def decrypt_lvl2(self, params, sk_a, C_a, **kwargs):
        if 'pk_a' not in kwargs: raise MissingRequiredKeywordArgumentError(['pk_a'])
        pk_a = kwargs['pk_a']
        sk_a_1 = sk_a['sk1']
        l, C0, C1, C2, C3, C4, sigma = C_a['l'], C_a['C0'], C_a['C1'], C_a['C2'], C_a['C3'], C_a['C4'], C_a['sigma']

        if not self._verify_sig(params, C_a):
            return None

        m = C3 / (pair(C1, params['g']) ** (1 / sk_a_1))
        return m
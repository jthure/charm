'''
LV11 - Proxy re-encryption.
| From: B. Libert and D. Vergnaud. (2011). Unidirectional Chosen-Ciphertext Secure Proxy Re-Encryption
| Published in: IEEE Transactions on Information Theory
* type:         proxy encryption
* properties:   RCCA-secure, unidirectional, single-Hop, collusion resistant, non-transistive, non-interactive.
* setting:      Pairing groups (Type 1 "symmetric")
* assumption:   eDBDH (Extended Decisional Bilinear DH)
:Authors:   M. Örndahl & J. Thuresson
:Date:      03/2018
'''
from charm.toolbox.pairinggroup import ZR, G1, G2, GT, pair
from charm.toolbox.UniPREnc_jm import UniPREnc


class LV11(UniPREnc):
    """
    Testing LV11 implementation

    >>> from charm.toolbox.pairinggroup import PairingGroup
    >>> from charm.schemes.pksig.lamport_jm import Lamport
    >>> groupObj = PairingGroup('SS512')
    >>> sigObj = Lamport()
    >>> pre = LV11(groupObj, sigObj)
    >>> params = pre.setup()
    >>> (pk_a, sk_a) = pre.keygen(params)
    >>> (pk_b, sk_b) = pre.keygen(params)
    >>> msg = groupObj.random(GT)
    >>> c_a1 = pre.encrypt_lvl1(params, pk_a, msg)
    >>> c_a2 = pre.encrypt_lvl2(params, pk_a, msg)
    >>> rk = pre.re_keygen(params, sk_a, pk_b)
    >>> kwargs = {'pk_i': pk_a}
    >>> c_b = pre.re_encrypt(params, rk, c_a2, **kwargs)
    >>> dec_ca1 = pre.decrypt_lvl1(params, sk_a, c_a1, **kwargs)
    >>> assert msg == dec_ca1, 'Decryption of level 1 ciphertext was incorrect'
    >>> kwargs = {'pk_i': pk_b}
    >>> dec_cb = pre.decrypt_lvl1(params, sk_b, c_b, **kwargs)
    >>> assert msg == dec_cb, 'Decryption of level 1 re-encrypted ciphertext was incorrect'
    >>> kwargs = {'pk_i': pk_a}
    >>> dec_ca2 = pre.decrypt_lvl2(params, sk_a, c_a2, **kwargs)
    >>> assert msg == dec_ca2, 'Decryption of level 2 ciphertext was incorrect'
    """

    def __init__(self, group_obj, sig_obj, pre_compute=True):
        super().__init__()
        self.group = group_obj
        self.sig = sig_obj
        self.pre_compute = pre_compute

    def setup(self):
        g = self.group.random(G1)
        u = self.group.random(G1)
        v = self.group.random(G1)
        if self.pre_compute:
            g.initPP()
            v.initPP()
            u.initPP()
        params = {'G1': G1, 'GT': GT, 'g': g, 'u': u, 'v': v, 'sig': self.sig}
        return params

    def keygen(self, params, **kwargs):
        x1 = self.group.random(ZR)
        g_x1 = params['g'] ** x1
        if self.pre_compute:
            g_x1.initPP()
        return g_x1, x1

    def re_keygen(self, params, sk_a, pk_b, **kwargs):
        rk = pk_b ** (1 / sk_a)
        if self.pre_compute:
            rk.initPP()
        return rk

    def encrypt_lvl1(self, params, pk_i, m, **kwargs):
        (svk, ssk) = params['sig'].keygen()
        r, t = self.group.random(ZR), self.group.random(ZR)

        C1 = svk
        C2_1 = pk_i ** t
        C2_2 = params['g'] ** (1 / t)
        C2_3 = pk_i ** (r * t)
        C3 = (pair(params['g'], params['g']) ** r) * m
        C4 = ((params['u'] ** self.group.hash(svk)) * params['v']) ** r

        sigma = params['sig'].sign(svk, ssk, self.group.serialize(C3) + self.group.serialize(C4))

        C_i = {'C1': C1, 'C2_1': C2_1, 'C2_2': C2_2, 'C2_3': C2_3, 'C3': C3, 'C4': C4, 'sigma': sigma}
        return C_i

    def encrypt_lvl2(self, params, pk_i, m, **kwargs):
        (svk, ssk) = params['sig'].keygen()
        r = self.group.random(ZR)

        C1 = svk
        C2 = pk_i ** r
        C3 = (pair(params['g'], params['g']) ** r) * m
        C4 = ((params['u'] ** self.group.hash(svk)) * params['v']) ** r

        sigma = params['sig'].sign(svk, ssk, self.group.serialize(C3) + self.group.serialize(C4))

        C = {'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4, 'sigma': sigma}
        return C

    def re_encrypt(self, params, rk, C_i, **kwargs):
        if 'pk_i' not in kwargs: return
        pk_i = kwargs['pk_i']
        if pair(C_i['C2'], (params['u'] ** self.group.hash(C_i['C1']) * params['v'])) != pair(
                pk_i, C_i['C4']):
            print("Re-encryption failed, case 1")
            return
        if not params['sig'].verify(C_i['C1'], self.group.serialize(C_i['C3']) + self.group.serialize(C_i['C4']),
                                    C_i['sigma']):
            print("Re-encryption failed, case 2")
            return

        t = self.group.random(ZR)
        C2_1 = pk_i ** t
        C2_2 = rk ** (1 / t)
        C2_3 = C_i['C2'] ** t

        C_j = {'C1': C_i['C1'], 'C2_1': C2_1, 'C2_2': C2_2, 'C2_3': C2_3, 'C3': C_i['C3'], 'C4': C_i['C4'],
               'sigma': C_i['sigma']}
        return C_j

    def decrypt_lvl1(self, params, sk_j, C_j, **kwargs):
        if 'pk_i' not in kwargs: return
        pk_i = kwargs['pk_i']
        if pair(C_j['C2_1'], C_j['C2_2']) != pair(pk_i, params['g']):
            print("Decryption1 failed, case 1")
            return
        if pair(C_j['C2_3'], (params['u'] ** self.group.hash(C_j['C1'])) * params['v']) != pair(
                C_j['C2_1'], C_j['C4']):
            print("Decryption1 failed, case 2")
            return
        if not params['sig'].verify(C_j['C1'], self.group.serialize(C_j['C3']) + self.group.serialize(C_j['C4']),
                                    C_j['sigma']):
            print("Decryption1 failed, case 3")
            return
        m = C_j['C3'] / pair(C_j['C2_2'], C_j['C2_3']) ** (1 / sk_j)
        return m

    def decrypt_lvl2(self, params, sk_i, C_i, **kwargs):
        if 'pk_i' not in kwargs: return
        pk_i = kwargs['pk_i']
        if pair(C_i['C2'], ((params['u'] ** self.group.hash(C_i['C1'])) * params['v'])) != pair(
                pk_i, C_i['C4']):
            print("Decryption2 failed, case 1")
            return
        if not params['sig'].verify(C_i['C1'], self.group.serialize(C_i['C3']) + self.group.serialize(C_i['C4']),
                                    C_i['sigma']):
            print("Decryption2 failed, case 2")
            return

        m = C_i['C3'] / pair(C_i['C2'], params['g']) ** (1 / sk_i)
        return m

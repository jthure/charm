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
from charm.toolbox.UniPREnc_jm import MissingRequiredKeywordArgumentError
from charm.schemes.prenc.pre_lv11_jm import LV11


class LV11Time(LV11):
    """
    Testing LV11 implementation

    >>> from charm.toolbox.pairinggroup import PairingGroup
    >>> from charm.schemes.pksig.lamport_jm import Lamport
    >>> groupObj = PairingGroup('SS512')
    >>> sigObj = Lamport()
    >>> pre = LV11Time(groupObj, sigObj)
    >>> params = pre.setup()

    >>> (pk_a, sk_a) = pre.keygen(params)
    >>> (pk_b, sk_b) = pre.keygen(params)

    >>> ts_2017 = pre.sign_timestamp(sk_a, '2017')
    >>> ts_2018 = pre.sign_timestamp(sk_a, '2018')

    >>> msg = groupObj.random(GT)

    >>> c_a1 = pre.encrypt_lvl1(params, pk_a, msg)
    >>> c_a2_2017 = pre.encrypt_lvl2(params, pk_a, msg, signed_timestamp=ts_2017)
    >>> c_a2_2018 = pre.encrypt_lvl2(params, pk_a, msg, signed_timestamp=ts_2018)

    >>> rk_2017 = pre.re_keygen(params, sk_a, pk_b, signed_timestamp=ts_2017)
    >>> rk_2018 = pre.re_keygen(params, sk_a, pk_b, signed_timestamp=ts_2018)

    >>> dec_ca1 = pre.decrypt_lvl1(params, sk_a, c_a1, pk_i=pk_a)
    >>> assert msg == dec_ca1, 'Decryption of level 1 ciphertext was incorrect'

    >>> c_b_2017 = pre.re_encrypt(params, rk_2017, c_a2_2017, pk_i=pk_a)
    >>> dec_cb_2017 = pre.decrypt_lvl1(params, sk_b, c_b_2017, pk_i=pk_b, signed_timestamp=ts_2017)
    >>> assert msg == dec_cb_2017, 'Decryption of level 1 re-encrypted ciphertext was incorrect'

    >>> c_b_2018 = pre.re_encrypt(params, rk_2018, c_a2_2017, pk_i=pk_a)
    >>> dec_cb_2018 = pre.decrypt_lvl1(params, sk_b, c_b_2018, pk_i=pk_b, signed_timestamp=ts_2017)
    Decryption1 failed, case 1
    >>> assert msg != dec_cb_2018, 'Decryption of level 1 re-encrypted ciphertext was correct, should be incorrect'

    >>> dec_ca2 = pre.decrypt_lvl2(params, sk_a, c_a2_2017, pk_i=pk_a)
    >>> assert msg == dec_ca2, 'Decryption of level 2 ciphertext was incorrect'
    """

    def re_keygen(self, params, sk_a, pk_b, **kwargs): #check
        if 'signed_timestamp' not in kwargs: raise MissingRequiredKeywordArgumentError(['signed_timestamp'])
        ts = kwargs['signed_timestamp']
        rk = pk_b ** (ts / sk_a)
        if self.pre_compute:
            rk.initPP()
        return rk

    def encrypt_lvl2(self, params, pk_i, m, **kwargs):
        if 'signed_timestamp' not in kwargs: raise MissingRequiredKeywordArgumentError(['signed_timestamp'])
        ts = kwargs['signed_timestamp']
        (svk, ssk) = params['sig'].keygen()
        r = self.group.random(ZR)

        C1 = svk
        C2 = pk_i ** r
        C3 = (pair(params['g'], params['g']) ** (r * ts)) * m
        C4 = ((params['u'] ** self.group.hash(svk)) * params['v']) ** r
        C5 = params['g'] ** ts

        sigma = params['sig'].sign(svk, ssk, self.group.serialize(C3) + self.group.serialize(C4))

        C = {'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4, 'C5': C5, 'sigma': sigma}
        return C

    def re_encrypt(self, params, rk, C_i, **kwargs):
        if 'pk_i' not in kwargs: raise MissingRequiredKeywordArgumentError(['pk_i'])
        pk_i = kwargs['pk_i']
        if pair(C_i['C2'], (params['u'] ** self.group.hash(C_i['C1']) * params['v'])) != pair(pk_i, C_i['C4']):
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

        C_j = {'C1': C_i['C1'], 'C2_1': C2_1, 'C2_2': C2_2, 'C2_3': C2_3, 'C3': C_i['C3'], 'C4': C_i['C4'], 'C5': C_i['C5'], 'sigma': C_i['sigma']}
        return C_j

    def decrypt_lvl1(self, params, sk_j, C_j, **kwargs):
        if 'pk_i' not in kwargs: raise MissingRequiredKeywordArgumentError(['pk_i'])
        pk_i = kwargs['pk_i']
        if 'C5' in C_j:
            if pair(C_j['C2_1'], C_j['C2_2']) != pair(pk_i, C_j['C5']):
                print("Decryption1 failed, case 1")
                return
        else:
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
        if 'pk_i' not in kwargs: raise MissingRequiredKeywordArgumentError(['pk_i'])
        pk_i = kwargs['pk_i']
        if pair(C_i['C2'], ((params['u'] ** self.group.hash(C_i['C1'])) * params['v'])) != pair(
                pk_i, C_i['C4']):
            print("Decryption2 failed, case 1")
            return
        if not params['sig'].verify(C_i['C1'], self.group.serialize(C_i['C3']) + self.group.serialize(C_i['C4']),
                                    C_i['sigma']):
            print("Decryption2 failed, case 2")
            return

        m = C_i['C3'] / pair(C_i['C2'], C_i['C5']) ** (1 / sk_i)
        return m

    def sign_timestamp(self, sk, ts):
        ts = self.group.hash(ts)
        return ts ** sk
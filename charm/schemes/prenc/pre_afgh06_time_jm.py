from charm.schemes.prenc.pre_afgh06_jm import AFGH06
from charm.toolbox.pairinggroup import ZR, pair

debug=False
class AFGH06Time(AFGH06):
    """
    Testing AFGH06Time implementation

    >>> from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
    >>> groupObj = PairingGroup('SS512')
    >>> pre = AFGH06Time(groupObj)
    >>> params = pre.setup()
    >>> (pk_a, sk_a) = pre.keygen(params)
    >>> (pk_b, sk_b) = pre.keygen(params)
    >>> ts_2017 = pre.sign_timestamp(sk_a, '2017')
    >>> ts_2018 = pre.sign_timestamp(sk_a, '2018')
    >>> msg = groupObj.random(GT)
    >>> c_a_1 = pre.encrypt_lvl1(params, pk_a, msg)
    >>> assert msg == pre.decrypt_lvl1(params, sk_a, c_a_1), 'Decryption of non re-encrypted lvl 1 ciphertext was incorrect'
    >>> c_a_2_2018 = pre.encrypt_lvl2(params, pk_a, msg, signed_timestamp=ts_2018)
    >>> assert msg == pre.decrypt_lvl2(params, sk_a, c_a_2_2018, signed_timestamp=ts_2018), 'Decryption of non re-encrypted lvl 2 with correct timestamp ciphertext was incorrect'
    >>> assert msg != pre.decrypt_lvl2(params, sk_a, c_a_2_2018, signed_timestamp=ts_2017), 'Decryption of non re-encrypted lvl 2 with incorrect timestamp ciphertext was correct. Should be incorrect'
    >>> rk_2017 = pre.re_keygen(params, sk_a, pk_b, signed_timestamp=ts_2017)
    >>> rk_2018 = pre.re_keygen(params, sk_a, pk_b, signed_timestamp=ts_2018)
    >>> c_b_2018_correct = pre.re_encrypt(params, rk_2018, c_a_2_2018)
    >>> c_b_2018_incorrect = pre.re_encrypt(params, rk_2017, c_a_2_2018)
    >>> assert msg == pre.decrypt_lvl1(params, sk_b, c_b_2018_correct), 'Decryption of re-encrypted ciphertext was incorrect'
    >>> assert msg != pre.decrypt_lvl1(params, sk_b, c_b_2018_incorrect), 'Decryption of incorrectly re-encrypted ciphertext was correct. Should be incorrect'
    """
    def re_keygen(self, params, sk_a, pk_b, **kwargs):
        if 'signed_timestamp' not in kwargs: return None
        ts = kwargs['signed_timestamp']
        pk_b2 = pk_b['pk2']
        sk_a1 = sk_a['sk1']
        rk = pk_b2 ** (sk_a1 * ts)
        if (debug):
            print('\nReKeyGen...')
            print("rk => '%s'" % rk)
        return rk

    def encrypt_lvl2(self, params, pk, m, **kwargs):
        if 'signed_timestamp' not in kwargs: return None
        ts = kwargs['signed_timestamp']
        r = self.group.random(ZR)
        Z_a1 = pk['pk1']
        c1 = params['g'] ** r
        c2 = m * (Z_a1 ** (r * ts))
        c = {'c1': c1, 'c2': c2}
        return c

    def decrypt_lvl2(self, params, sk, c, **kwargs):
        if 'signed_timestamp' not in kwargs: return None
        ts = kwargs['signed_timestamp']
        c1 = c['c1']
        c2 = c['c2']
        g = params['g']
        m = c2 / pair(c1, g ** (sk['sk1'] * ts))

        return m

    def sign_timestamp(self, sk, ts):
        sk_a1 = sk['sk1']
        ts = self.group.hash(ts)
        return ts ** sk_a1
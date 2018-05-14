from charm.toolbox.UniPREnc_jm import MissingRequiredKeywordArgumentError
from charm.schemes.prenc.pre_afgh06_jm import AFGH06
from charm.toolbox.pairinggroup import ZR, pair

debug = False


class AFGH06Temp(AFGH06):
    """
    Testing AFGH06Time implementation

    >>> from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
    >>> groupObj = PairingGroup('SS512')
    >>> pre = AFGH06Temp(groupObj)
    >>> params = pre.setup()
    >>> (pk_a, sk_a) = pre.keygen(params)
    >>> (pk_b, sk_b) = pre.keygen(params)
    >>> # ts_2017 = pre.sign_timestamp(sk_a, '2017')
    >>> # ts_2018 = pre.sign_timestamp(sk_a, '2018')
    >>> msg = groupObj.random(GT)
    >>> c_a_1 = pre.encrypt_lvl1(params, pk_a, msg)
    >>> assert msg == pre.decrypt_lvl1(params, sk_a, c_a_1), 'Decryption of non re-encrypted lvl 1 ciphertext was incorrect'
    >>> c_a_2_2018 = pre.encrypt_lvl2(params, pk_a, msg, l='2018')
    >>> assert msg == pre.decrypt_lvl2(params, sk_a, c_a_2_2018, l='2018'), 'Decryption of non re-encrypted lvl 2 with correct timestamp ciphertext was incorrect'
    >>> assert msg != pre.decrypt_lvl2(params, sk_a, c_a_2_2018, l='2017'), 'Decryption of non re-encrypted lvl 2 with incorrect timestamp ciphertext was correct. Should be incorrect'
    >>> rk_2017 = pre.re_keygen(params, sk_a, pk_b, l='2017')
    >>> rk_2018 = pre.re_keygen(params, sk_a, pk_b, l='2018')
    >>> c_b_2018_correct = pre.re_encrypt(params, rk_2018, c_a_2_2018)
    >>> c_b_2018_incorrect = pre.re_encrypt(params, rk_2017, c_a_2_2018)
    >>> assert msg == pre.decrypt_lvl1(params, sk_b, c_b_2018_correct), 'Decryption of re-encrypted ciphertext was incorrect'
    >>> assert msg != pre.decrypt_lvl1(params, sk_b, c_b_2018_incorrect), 'Decryption of incorrectly re-encrypted ciphertext was correct. Should be incorrect'
    """

    def re_keygen(self, params, sk_a, pk_b, **kwargs):
        '''
        Additionally requires kwarg 'l' to be passed
        :param params:
        :param sk_a:
        :param pk_b:
        :param kwargs:
        :return:
        '''
        if 'l' not in kwargs: raise MissingRequiredKeywordArgumentError(['l'])
        l = kwargs['l']
        pk_b2 = pk_b['pk2']
        sk_a1 = sk_a['sk1']
        sk_a2 = sk_a['sk2']
        rk = pk_b2 ** (sk_a1 / (self.group.hash(l) + sk_a2))
        if (debug):
            print('\nReKeyGen...')
            print("rk => '%s'" % rk)
        return rk

    def encrypt_lvl2(self, params, pk, m, **kwargs):
        if 'l' not in kwargs: raise MissingRequiredKeywordArgumentError(['l'])
        l = self.group.hash(kwargs['l'])
        r = self.group.random(ZR)
        Z_a1 = pk['pk1']
        g_a2 = pk['pk2']
        c1 = (g_a2 ** r) * (params['g'] ** (l * r))
        c2 = m * (Z_a1 ** r)
        c = {'c1': c1, 'c2': c2}
        return c

    def decrypt_lvl2(self, params, sk, c, **kwargs):
        if 'l' not in kwargs: raise MissingRequiredKeywordArgumentError(['l'])
        l = self.group.hash(kwargs['l'])
        c1 = c['c1']
        c2 = c['c2']
        g = params['g']
        sk_a1, sk_a2 = sk['sk1'], sk['sk2']
        m = c2 / pair(c1, g ** (sk_a1 / (sk_a2 + l)))
        return m

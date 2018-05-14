from charm.toolbox.UniPREnc_jm import UniPREnc
from charm.core.crypto.cryptobase import AES
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair, extract_key

debug = False


class HybridUniPREnc(UniPREnc):
    '''
    >>> from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
    >>> from charm.schemes.prenc.pre_afgh06_jm import  AFGH06
    >>> from charm.schemes.prenc.pre_lv11_jm import  LV11
    >>> import os
    >>> groupObj = PairingGroup('SS512')
    >>> pre = AFGH06(groupObj)
    >>> hyb = HybridUniPREnc(pre)
    >>> params = hyb.setup()
    >>> (pk_a, sk_a) = hyb.keygen(params)
    >>> (pk_b, sk_b) = hyb.keygen(params)
    >>> msg = os.urandom(1000 * 1)
    >>> c_a_1 = hyb.encrypt_lvl1(params, pk_a, msg)
    >>> assert msg == hyb.decrypt_lvl1(params, sk_a, c_a_1), 'Decryption of non re-encrypted lvl 1 ciphertext was incorrect'
    >>> c_a_2 = hyb.encrypt_lvl2(params, pk_a, msg)
    >>> assert msg == hyb.decrypt_lvl2(params, sk_a, c_a_2), 'Decryption of non re-encrypted lvl 2 ciphertext was incorrect'
    >>> rk = hyb.re_keygen(params, sk_a, pk_b)
    >>> c_b = hyb.re_encrypt(params, rk, c_a_2)
    >>> assert msg == hyb.decrypt_lvl1(params, sk_b, c_b), 'Decryption of re-encrypted ciphertext was incorrect'
    '''

    def __init__(self, prenc, msg_len=16, key_len=16, mode=AES):
        UniPREnc.__init__(self)
        # check that prenc satisfies properties of a prenc scheme
        if hasattr(prenc, 'keygen') and hasattr(prenc, 'encrypt_lvl1') and hasattr(prenc, 'decrypt_lvl2')\
                and hasattr(prenc, 'encrypt_lvl2') and hasattr(prenc, 'decrypt_lvl2')\
                and hasattr(prenc, 're_encrypt') and hasattr(prenc, 're_keygen'):
            self.prenc = prenc
            self.key_len = key_len  # 128-bit session key by default
            self.msg_len = msg_len
            self.alg = mode
            if debug: print("PKEnc satisfied.")

    def setup(self):
        return self.prenc.setup()

    def keygen(self, params, **kwargs):
        return self.prenc.keygen(params, **kwargs)

    def re_keygen(self, params, sk_a, pk_b, **kwargs):
        return self.prenc.re_keygen(params, sk_a, pk_b, **kwargs)

    def encrypt_lvl1(self, params, pk, M, **kwargs):
        key = self.prenc.group.random(GT)
        c1 = self.prenc.encrypt_lvl1(params, pk, key, **kwargs)
        c2 = AuthenticatedCryptoAbstraction(extract_key(key)).encrypt(M)
        if debug:
            print("Ciphertext...")
        if debug:
            print(c2)
        return {'c1': c1, 'c2': c2}

    def encrypt_lvl2(self, params, pk, M, **kwargs):
        key = self.prenc.group.random(GT)
        c1 = self.prenc.encrypt_lvl2(params, pk, key, **kwargs)
        c2 = AuthenticatedCryptoAbstraction(extract_key(key)).encrypt(M)
        if debug:
            print("Ciphertext...")
        if debug:
            print(c2)
        return {'c1': c1, 'c2': c2}

    def re_encrypt(self, params, rk, c, **kwargs):
        c1, c2 = c['c1'], c['c2']
        c1 = self.prenc.re_encrypt(params, rk, c1, **kwargs)
        return {'c1': c1, 'c2': c2}

    def decrypt_lvl1(self, params, sk, c, **kwargs):
        c1, c2 = c['c1'], c['c2']
        key = self.prenc.decrypt_lvl1(params, sk, c1, **kwargs)
        msg = AuthenticatedCryptoAbstraction(extract_key(key)).decrypt(c2)
        return msg

    def decrypt_lvl2(self, params, sk, c, **kwargs):
        c1, c2 = c['c1'], c['c2']
        key = self.prenc.decrypt_lvl2(params, sk, c1, **kwargs)
        msg = AuthenticatedCryptoAbstraction(extract_key(key)).decrypt(c2)
        return msg

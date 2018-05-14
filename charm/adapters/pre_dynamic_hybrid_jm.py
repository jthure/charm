from charm.toolbox.UniPREnc_jm import UniPREnc
from charm.core.crypto.cryptobase import AES
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction, SymmetricCryptoAbstraction
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair, extract_key

debug = False


class HybridDynamicUniPREnc(UniPREnc):
    '''
    >>> from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
    >>> from charm.schemes.prenc.pre_afgh06_jm import  AFGH06
    >>> from charm.schemes.prenc.pre_lv11_jm import  LV11
    >>> groupObj = PairingGroup('SS512')
    >>> pre = AFGH06(groupObj)
    >>> hyb = HybridDynamicUniPREnc(pre)
    >>> params = hyb.setup()
    >>> (pk_a, sk_a) = hyb.keygen(params)
    >>> (pk_b, sk_b) = hyb.keygen(params)
    >>> msg = b'Hi there!'
    >>> # Regular non-dynamic should work as usual
    >>> c_a_1, _ = hyb.encrypt_lvl1(params, pk_a, msg)
    >>> assert msg == hyb.decrypt_lvl1(params, sk_a, c_a_1)[0], 'Decryption of non re-encrypted lvl 1 ciphertext was incorrect'
    >>> c_a_2, _ = hyb.encrypt_lvl2(params, pk_a, msg)
    >>> assert msg == hyb.decrypt_lvl2(params, sk_a, c_a_2)[0], 'Decryption of non re-encrypted lvl 2 ciphertext was incorrect'
    >>> rk = hyb.re_keygen(params, sk_a, pk_b)
    >>> c_b, _ = hyb.re_encrypt(params, rk, c_a_2)
    >>> assert msg == hyb.decrypt_lvl1(params, sk_b, c_b)[0], 'Decryption of re-encrypted ciphertext was incorrect'
    >>> # Test the dynamic functionality. The second re-encryption and decryption are very cheap since we reuse the symmetric key
    >>> c_a_2_1, sym_key = hyb.encrypt_lvl2(params, pk_a, msg)
    >>> c_a_2_2, sym_key = hyb.encrypt_lvl2(params, pk_a, msg, sym_key=sym_key)
    >>> c_b_1_1, sym_key_reenc = hyb.re_encrypt(params, rk, c_a_2_1)
    >>> c_b_1_2, sym_key_reenc = hyb.re_encrypt(params, rk, c_a_2_2, sym_key_reenc=sym_key_reenc)
    >>> dec_msg, sym_key = hyb.decrypt_lvl1(params, sk_b, c_b_1_1)
    >>> assert dec_msg == msg, 'Decryption of re-encrypted ciphertext was incorrect'
    >>> dec_msg, sym_key = hyb.decrypt_lvl1(params, sk_b, c_b_1_1, sym_key=sym_key)
    >>> assert dec_msg == msg, 'Decryption of dynamic re-encrypted ciphertext was incorrect'


    '''

    def __init__(self, prenc, msg_len=16, key_len=16, mode=AES):
        UniPREnc.__init__(self)
        # check that prenc satisfies properties of a prenc scheme
        if hasattr(prenc, 'keygen') and hasattr(prenc, 'encrypt_lvl1') and hasattr(prenc, 'decrypt_lvl2') \
                and hasattr(prenc, 'encrypt_lvl2') and hasattr(prenc, 'decrypt_lvl2') \
                and hasattr(prenc, 're_encrypt') and hasattr(prenc, 're_keygen'):
            self.prenc = prenc
            self.key_len = key_len  # 128-bit session key by default
            self.msg_len = msg_len
            self.alg = mode
            if debug: print("PREnc satisfied.")
        self.sym_key = self.sym_key_encrypted = self.sym_key_reencrypted = self.sym_key_decrypted = None

    def setup(self):
        return self.prenc.setup()

    def keygen(self, params, **kwargs):
        return self.prenc.keygen(params, **kwargs)

    def re_keygen(self, params, sk_a, pk_b, **kwargs):
        return self.prenc.re_keygen(params, sk_a, pk_b, **kwargs)

    def encrypt_lvl1(self, params, pk, M, **kwargs):
        if 'sym_key' in kwargs:
            sym_key, sym_key_enc = kwargs['sym_key']['key'], kwargs['sym_key']['key_enc']
        else:
            sym_key = self.prenc.group.random(GT)
            sym_key_enc = self.prenc.encrypt_lvl1(params, pk, sym_key, **kwargs)
        c1 = sym_key_enc
        c2 = AuthenticatedCryptoAbstraction(extract_key(sym_key)).encrypt(M)
        if debug:
            print("Ciphertext...")
        if debug:
            print(c2)
        return {'c1': c1, 'c2': c2}, {'key': sym_key, 'key_enc': sym_key_enc}

    def encrypt_lvl2(self, params, pk, M, **kwargs):
        if 'sym_key' in kwargs:
            sym_key, sym_key_enc = kwargs['sym_key']['key'], kwargs['sym_key']['key_enc']
        else:
            sym_key = self.prenc.group.random(GT)
            sym_key_enc = self.prenc.encrypt_lvl2(params, pk, sym_key, **kwargs)
        c1 = sym_key_enc
        c2 = AuthenticatedCryptoAbstraction(extract_key(sym_key)).encrypt(M)
        if debug:
            print("Ciphertext...")
        if debug:
            print(c2)
        return {'c1': c1, 'c2': c2}, {'key': sym_key, 'key_enc': sym_key_enc}

    def re_encrypt(self, params, rk, c, **kwargs):
        c1, c2 = c['c1'], c['c2']
        if 'sym_key_reenc' in kwargs:
            sym_key_reenc = kwargs['sym_key_reenc']
        else:
            sym_key_reenc = self.prenc.re_encrypt(params, rk, c1, **kwargs)
        c1 = sym_key_reenc
        return {'c1': c1, 'c2': c2}, sym_key_reenc

    def decrypt_lvl1(self, params, sk, c, **kwargs):
        if 'sym_key' in kwargs:
            sym_key = kwargs['sym_key']
        else:
            c1 = c['c1']
            sym_key = self.prenc.decrypt_lvl1(params, sk, c1, **kwargs)
        c2 = c['c2']
        msg = AuthenticatedCryptoAbstraction(extract_key(sym_key)).decrypt(c2)
        return msg, sym_key

    def decrypt_lvl2(self, params, sk, c, **kwargs):
        if 'sym_key' in kwargs:
            sym_key = kwargs['sym_key']
        else:
            c1 = c['c1']
            sym_key = self.prenc.decrypt_lvl2(params, sk, c1, **kwargs)
        c2 = c['c2']
        msg = AuthenticatedCryptoAbstraction(extract_key(sym_key)).decrypt(c2)
        return msg, sym_key

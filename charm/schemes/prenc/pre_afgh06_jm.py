'''
AFGH Proxy Re-Encryption
| From: Ateniese, G., Fu, K., Green, M., & Hohenberger, S. (2006). Improved proxy re-encryption schemes with applications to secure distributed storage. 
| Published in: ACM Transactions on Information and System Security (TISSEC), 9(1), 1-30.
| Available from: http://dl.acm.org/citation.cfm?id=1127346
* type:           proxy encryption
* properties:     CPA-secure, unidirectional, single-hop, non-interactive, collusion-resistant
* setting:        Pairing groups (Type 1 "symmetric")
* assumption:     eDBDH (Extended Decisional Bilinear DH)
* to-do:          first-level encryption & second-level decryption
:Authors:    D. Nuñez
:Date:       04/2016
'''
from charm.toolbox.pairinggroup import ZR,G1,pair
from charm.toolbox.UniPREnc_jm import UniPREnc

debug = False


class AFGH06(UniPREnc):
    """
    Testing AFGH06 implementation 

    >>> from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
    >>> groupObj = PairingGroup('SS512')
    >>> pre = AFGH06(groupObj)
    >>> params = pre.setup()
    >>> (pk_a, sk_a) = pre.keygen(params)
    >>> (pk_b, sk_b) = pre.keygen(params)
    >>> msg = groupObj.random(GT)
    >>> c_a_1 = pre.encrypt_lvl1(params, pk_a, msg)
    >>> assert msg == pre.decrypt_lvl1(params, sk_a, c_a_1), 'Decryption of non re-encrypted lvl 1 ciphertext was incorrect'
    >>> c_a_2 = pre.encrypt_lvl2(params, pk_a, msg)
    >>> assert msg == pre.decrypt_lvl2(params, sk_a, c_a_2), 'Decryption of non re-encrypted lvl 2 ciphertext was incorrect'
    >>> rk = pre.re_keygen(params, sk_a, pk_b)
    >>> c_b = pre.re_encrypt(params, rk, c_a_2)
    >>> assert msg == pre.decrypt_lvl1(params, sk_b, c_b), 'Decryption of re-encrypted ciphertext was incorrect'
    """

    def __init__(self, group_obj, pre_compute=True):
        super().__init__()
        self.group = group_obj
        self.pre_compute = pre_compute

    def setup(self):
        g = self.group.random(G1)
        Z = pair(g, g)

        if self.pre_compute:
            g.initPP()
            Z.initPP()

        params = {'g': g, 'Z': Z}
        if (debug):
            print("Setup: Public parameters...")
            self.group.debug(params)
        return params

    def keygen(self, params, **kwargs):
        x1, x2 = self.group.random(ZR), self.group.random(ZR)
        Z_x1 = params['Z'] ** x1
        g_x2 = params['g'] ** x2
        if self.pre_compute:
            Z_x1.initPP()
            g_x2.initPP()
        sk = {'sk1': x1, 'sk2': x2}
        pk = {'pk1': Z_x1, 'pk2': g_x2}

        if (debug):
            print('\nKeygen...')
            print("pk => '%s'" % pk)
            print("sk => '%s'" % sk)
        return (pk, sk)

    def re_keygen(self, params, sk_a, pk_b, **kwargs):
        pk_b2 = pk_b['pk2']
        sk_a1 = sk_a['sk1']
        rk = pk_b2 ** sk_a1
        if (debug):
            print('\nReKeyGen...')
            print("rk => '%s'" % rk)
        return rk

    def encrypt_lvl1(self, params, pk, m, **kwargs):
        r = self.group.random(ZR)

        Z = params['Z']
        Z_a2 = pair(params['g'], pk['pk2'])
        c1 = Z_a2 ** r
        c2 = m * (Z ** r)

        c = {'c1': c1, 'c2': c2}

        if (debug):
            print('\nEncrypt...')
            print('m => %s' % m)
            print('r => %s' % r)
            self.group.debug(c)
        return c

    def encrypt_lvl2(self, params, pk, m, **kwargs):
        r = self.group.random(ZR)

        Z_a1 = pk['pk1']

        c1 = params['g'] ** r
        c2 = m * (Z_a1 ** r)

        c = {'c1': c1, 'c2': c2}

        if (debug):
            print('\nEncrypt...')
            print('m => %s' % m)
            print('r => %s' % r)
            self.group.debug(c)
        return c

    def decrypt_lvl1(self, params, sk, c, **kwargs):
        c1 = c['c1']
        c2 = c['c2']
        m = c2 / (c1 ** (~sk['sk2']))

        if (debug):
            print('\nDecrypt...')
            print('m => %s' % m)

        return m

    def decrypt_lvl2(self, params, sk, c, **kwargs):
        c1 = c['c1']
        c2 = c['c2']
        g = params['g']
        m = c2 / pair(c1, g ** sk['sk1'])

        if (debug):
            print('\nDecrypt...')
            print('m => %s' % m)

        return m

    def re_encrypt(self, params, rk, c_a, **kwargs):
        c1 = c_a['c1']
        c2 = c_a['c2']

        c1_prime = pair(c1, rk)

        c_b = {'c1': c1_prime, 'c2': c2}
        if (debug):
            print('\nRe-encrypt...')
            self.group.debug(c_b)
        return c_b

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
groupObj = PairingGroup('SS512')
pre = AFGH06(groupObj)
params = pre.setup()
(pk_a, sk_a) = pre.keygen(params)
(pk_b, sk_b) = pre.keygen(params)
rk = pre.re_keygen(params, sk_a, pk_b)
print(groupObj.serialize(rk, compression=False))
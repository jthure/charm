from charm.schemes.abenc.abenc_waters09_jm import CPabe09
from _functools import reduce

class CPabe09CCA(CPabe09):
    """
    >>> from charm.toolbox.pairinggroup import PairingGroup,GT
    >>> from charm.schemes.pksig.lamport_jm import Lamport
    >>> group = PairingGroup('SS512')
    >>> sig_obj = Lamport()
    >>> cpabe = CPabe09CCA(group, sig_obj)
    >>> msg = group.random(GT)
    >>> (master_secret_key, master_public_key) = cpabe.setup()
    >>> policy = '((ONE or THREE) and (TWO or FOUR))'
    >>> attr_list = ['THREE', 'ONE', 'TWO']
    >>> secret_key = cpabe.keygen(master_public_key, master_secret_key, attr_list)
    >>> cipher_text = cpabe.encrypt(master_public_key, msg, policy)
    >>> decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
    >>> decrypted_msg == msg
    True
    """

    def __init__(self, group_obj, sig_obj, pre_compute=True):
        super().__init__(group_obj, pre_compute)
        self.sig = sig_obj

    def encrypt(self, pk, M, policy_str):
        CT = super().encrypt(pk, M, policy_str)
        C0, C, D, C_tilde = CT['C0'], CT['C'], CT['D'], CT['C_tilde']
        serialized_data = self.group.serialize(C0) + self.group.serialize(C_tilde)
        serialized_data = reduce(lambda acc, item: acc + self.group.serialize(item[1]),
                                 sorted(list(C.items()), key=lambda x: x[0]) + sorted(list(D.items()), key=lambda x: x[0]),
                                 serialized_data)
        svk, ssk = self.sig.keygen()
        return svk, CT, self.sig.sign(None, ssk, serialized_data)

    def decrypt(self, pk, sk, ct_tilde):
        svk, CT, sigma = ct_tilde
        C0, C, D, C_tilde = CT['C0'], CT['C'], CT['D'], CT['C_tilde']
        serialized_data = self.group.serialize(C0) + self.group.serialize(C_tilde)
        serialized_data = reduce(lambda acc, item: acc + self.group.serialize(item[1]),
                                 sorted(list(C.items()), key=lambda x: x[0]) + sorted(list(D.items()), key=lambda x: x[0]),
                                 serialized_data)
        if self.sig.verify(svk, serialized_data, sigma):
            return super().decrypt(pk, sk, CT)
        return None
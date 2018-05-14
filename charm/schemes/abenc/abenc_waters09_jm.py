from charm.schemes.abenc.abenc_waters09 import CPabe09 as OrigCPabe09


class CPabe09(OrigCPabe09):
    """
    >>> from charm.toolbox.pairinggroup import PairingGroup,GT
    >>> from charm.schemes.pksig.lamport_jm import Lamport
    >>> group = PairingGroup('SS512')
    >>> cpabe = CPabe09(group)
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

    def __init__(self, group_obj, pre_compute=True):
        super().__init__(group_obj)
        self.pre_compute = pre_compute
        self.group = group_obj

    def setup(self):
        (msk, pk) = super().setup()
        if self.pre_compute:
            pk['g2'].initPP(), pk['g2^a'].initPP(), pk['e(gg)^alpha'].initPP(), pk['g1'].initPP(), pk['g1^a'].initPP(),
        return msk, pk

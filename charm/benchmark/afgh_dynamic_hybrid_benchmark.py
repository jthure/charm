from charm.schemes.prenc.pre_afgh06_temp_jm import AFGH06Temp
from charm.adapters.pre_dynamic_hybrid_jm import HybridDynamicUniPREnc
from charm.toolbox.pairinggroup import PairingGroup
from charm.benchmark.benchmark import benchmark
import os

iterations = 10

pairing_group = PairingGroup('SS512')
pre = AFGH06Temp(pairing_group)
hyb = HybridDynamicUniPREnc(pre)
assert pairing_group.InitBenchmark(), "failed to initialize utils"

params = hyb.setup()
(pk_a, sk_a) = hyb.keygen(params)
(pk_b, sk_b) = hyb.keygen(params)

rk_ab_2018 = hyb.re_keygen(params, sk_a, pk_b, l='2018')

data_size = int(1.5 * (10 ** 6)) // 2
fps = 15
ifps = 1

msg_array = [os.urandom(((data_size // 10) * 9) // ifps) for _ in range(ifps)] + [
    os.urandom(((data_size // 10) * 1) // (fps - ifps)) for _ in range(fps - ifps)
]


# Encrypt lvl2
def encrypt_lvl2():
    c, sym_key = hyb.encrypt_lvl2(params, pk_a, msg_array[0], l='2018')
    c_array = [c]
    for m in msg_array[1:]:
        c, _ = hyb.encrypt_lvl2(params, pk_a, m, sym_key=sym_key, l='2018')
        c_array.append(c)
    return c_array


def re_encrypt(rk, c_array):
    c_prime, sym_key = hyb.re_encrypt(params, rk, c_array[0])
    c_prime_array = [c_prime]
    for c in c_array[1:]:
        c_prime, _ = hyb.re_encrypt(params, rk, c, sym_key_reenc=sym_key, l='2018')
        c_prime_array.append(c_prime)
    return c_prime_array


def decrypt_lvl1(c_prime_array):
    msg_prime, sym_key = hyb.decrypt_lvl1(params, sk_b, c_prime_array[0])
    msg_prime_array = [msg_prime]
    for c_prime in c_prime_array[1:]:
        msg_prime, _ = hyb.decrypt_lvl1(params, sk_b, c_prime)
        msg_prime_array.append(msg_prime)
    return msg_prime_array


_benchmark = lambda func, title: benchmark(func, title, pairing_group, iterations, bm_flags=None)

c_array = _benchmark(encrypt_lvl2, 'Encrypt lvl2')
rk = _benchmark(lambda: hyb.re_keygen(params, sk_a, pk_b, l='2018'), 'Re-encryption key generation')
c_prime_array = _benchmark(lambda: re_encrypt(rk, c_array), 'Re-encryption')
msg_prime_array = _benchmark(lambda: decrypt_lvl1(c_prime_array), 'Decryption lvl2')

for msg, msg_prime in zip(msg_array, msg_prime_array):
    assert msg == msg_prime

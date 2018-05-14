from charm.schemes.prenc.pre_afgh06_jm import AFGH06
from charm.schemes.prenc.pre_afgh06_time_jm import AFGH06Time
from charm.schemes.prenc.pre_afgh06_temp_jm import AFGH06Temp
from charm.adapters.pre_hybrid_jm import HybridUniPREnc
from charm.toolbox.pairinggroup import PairingGroup, GT, order
import os

iterations = 100
bmFlags = ["RealTime", "CpuTime", "Div", "Mul", "Exp", "Pair", "Granular"]
group_obj = PairingGroup('SS512')


def normbm(bm, iterations):
    (gen, gran) = bm
    gen["CpuTime"] *= 10 ** 6
    gen["RealTime"] *= 10 ** 6
    for k, v in gen.items():
        gen[k] = v / iterations
    for k, l in gran.items():
        gran[k] = [v / iterations for v in l]
    return bm


def print_benchmark(title, bm):
    print(title + " =================================")
    (gen, gran) = bm
    string = "\tOperations:\t"
    for k, v in [(k1, v1) for k1, v1 in gen.items() if not (k1 == "RealTime" or k1 == "CpuTime")]:
        string += k + ": " + str(int(v)) + ", "
    print(string)
    string = "\tTime:\t\t"
    for k, v in [(k1, v1) for k1, v1 in gen.items() if (k1 == "RealTime" or k1 == "CpuTime")]:
        string += k + ": " + str(v) + " us, "
    print(string)


def benchmark(func, title):
    ret = None
    group_obj.StartBenchmark(bmFlags)
    for i in range(iterations):
        ret = func()
    group_obj.EndBenchmark()
    bm = (group_obj.GetGeneralBenchmarks(), group_obj.GetGranularBenchmarks())
    print_benchmark(title, normbm(bm, iterations))
    return ret


def benchmark_afgh06():
    print("AFGH06 BENCHMARK")
    pre = AFGH06(group_obj, pre_compute=True)
    params = pre.setup()
    (pk_a, sk_a) = pre.keygen(params)
    (pk_b, sk_b) = pre.keygen(params)
    # rk = pre.re_keygen(params, sk_a, pk_b)
    msg = group_obj.random(GT)

    assert group_obj.InitBenchmark(), "failed to initialize utils"

    c_a_1 = benchmark(lambda: pre.encrypt_lvl1(params, pk_a, msg), "Encryption lvl1")
    c_a_2 = benchmark(lambda: pre.encrypt_lvl2(params, pk_a, msg), "Encryption lvl2")
    rk = benchmark(lambda: pre.re_keygen(params, sk_a, pk_b), "Proxy re-encryption key generation")
    c_b_1 = benchmark(lambda: pre.re_encrypt(params, rk, c_a_2), "Re-encryption")
    msg2 = benchmark(lambda: pre.decrypt_lvl1(params, sk_a, c_a_1), "Decryption lvl1")
    msg2 = benchmark(lambda: pre.decrypt_lvl2(params, sk_a, c_a_2), "Decryption lvl2")
    msg2 = benchmark(lambda: pre.decrypt_lvl1(params, sk_b, c_b_1), "Decryption of re-encrypted")


def benchmark_afgh06_hybrid():
    print("AFGH06 Hybrid BENCHMARK")
    pre = AFGH06(group_obj)
    pre = HybridUniPREnc(pre)
    params = pre.setup()
    (pk_a, sk_a) = pre.keygen(params)
    (pk_b, sk_b) = pre.keygen(params)
    # rk = pre.re_keygen(params, sk_a, pk_b)
    msg = os.urandom(1000 * 1)

    assert group_obj.InitBenchmark(), "failed to initialize utils"
    c_a_1 = benchmark(lambda: pre.encrypt_lvl1(params, pk_a, msg), "Encryption lvl1")
    c_a_2 = benchmark(lambda: pre.encrypt_lvl2(params, pk_a, msg), "Encryption lvl2")
    rk = benchmark(lambda: pre.re_keygen(params, sk_a, pk_b), "Proxy re-encryption key generation")
    c_b_1 = benchmark(lambda: pre.re_encrypt(params, rk, c_a_2), "Re-encryption")
    msg2 = benchmark(lambda: pre.decrypt_lvl1(params, sk_a, c_a_1), "Decryption lvl1")
    msg2 = benchmark(lambda: pre.decrypt_lvl2(params, sk_a, c_a_2), "Decryption lvl2")
    msg2 = benchmark(lambda: pre.decrypt_lvl1(params, sk_b, c_b_1), "Decryption of re-encrypted")


def benchmark_afgh06_time():
    print("AFGH06Time BENCHMARK")
    pre = AFGH06Time(group_obj, pre_compute=False)
    params = pre.setup()
    (pk_a, sk_a) = pre.keygen(params)
    (pk_b, sk_b) = pre.keygen(params)
    ts_2018 = pre.sign_timestamp(sk_a, '2018')
    # rk = pre.re_keygen(params, sk_a, pk_b)
    msg = group_obj.random(GT)

    assert group_obj.InitBenchmark(), "failed to initialize utils"
    c_a_1 = benchmark(lambda: pre.encrypt_lvl1(params, pk_a, msg), "Encryption lvl1")
    c_a_2 = benchmark(lambda: pre.encrypt_lvl2(params, pk_a, msg, signed_timestamp=ts_2018), "Encryption lvl2")
    rk = benchmark(lambda: pre.re_keygen(params, sk_a, pk_b, signed_timestamp=ts_2018),
                   "Proxy re-encryption key generation")
    c_b_1 = benchmark(lambda: pre.re_encrypt(params, rk, c_a_2), "Re-encryption")
    msg2 = benchmark(lambda: pre.decrypt_lvl1(params, sk_a, c_a_1), "Decryption lvl1")
    msg2 = benchmark(lambda: pre.decrypt_lvl2(params, sk_a, c_a_2, signed_timestamp=ts_2018), "Decryption lvl2")
    msg2 = benchmark(lambda: pre.decrypt_lvl1(params, sk_b, c_b_1), "Decryption of re-encrypted")


def benchmark_afgh06_time_hybrid():
    print("AFGH06Time Hybrid BENCHMARK")
    pre = AFGH06Time(group_obj)
    hyb = HybridUniPREnc(pre)
    params = hyb.setup()
    (pk_a, sk_a) = hyb.keygen(params)
    (pk_b, sk_b) = hyb.keygen(params)
    ts_2018 = pre.sign_timestamp(sk_a, '2018')
    # rk = hyb.re_keygen(params, sk_a, pk_b)
    msg = os.urandom(1000 * 1000)

    assert group_obj.InitBenchmark(), "failed to initialize utils"
    rk = benchmark(lambda: hyb.re_keygen(params, sk_a, pk_b, signed_timestamp=ts_2018),
                   "Proxy re-encryption key generation")
    c_a_1 = benchmark(lambda: hyb.encrypt_lvl1(params, pk_a, msg), "Encryption lvl1")
    c_a_2 = benchmark(lambda: hyb.encrypt_lvl2(params, pk_a, msg, signed_timestamp=ts_2018), "Encryption lvl2")
    msg2 = benchmark(lambda: hyb.decrypt_lvl1(params, sk_a, c_a_1), "Decryption lvl1")
    msg2 = benchmark(lambda: hyb.decrypt_lvl2(params, sk_a, c_a_2, signed_timestamp=ts_2018), "Decryption lvl2")
    c_b_1 = benchmark(lambda: hyb.re_encrypt(params, rk, c_a_2), "Re-encryption")
    msg2 = benchmark(lambda: hyb.decrypt_lvl1(params, sk_b, c_b_1), "Decryption of re-encrypted")


def benchmark_afgh06_temp():
    print("AFGH06Temp BENCHMARK")
    pre = AFGH06Temp(group_obj, pre_compute=True)
    params = pre.setup()
    (pk_a, sk_a) = pre.keygen(params)
    (pk_b, sk_b) = pre.keygen(params)
    msg = group_obj.random(GT)

    assert group_obj.InitBenchmark(), "failed to initialize utils"
    c_a_1 = benchmark(lambda: pre.encrypt_lvl1(params, pk_a, msg), "Encryption lvl1")
    c_a_2 = benchmark(lambda: pre.encrypt_lvl2(params, pk_a, msg, l='2018'), "Encryption lvl2")
    rk = benchmark(lambda: pre.re_keygen(params, sk_a, pk_b, l='2018'), "Proxy re-encryption key generation")
    c_b_1 = benchmark(lambda: pre.re_encrypt(params, rk, c_a_2), "Re-encryption")
    msg2 = benchmark(lambda: pre.decrypt_lvl1(params, sk_a, c_a_1), "Decryption lvl1")
    msg2 = benchmark(lambda: pre.decrypt_lvl2(params, sk_a, c_a_2, l='2018'), "Decryption lvl2")
    msg2 = benchmark(lambda: pre.decrypt_lvl1(params, sk_b, c_b_1), "Decryption of re-encrypted")


def benchmark_afgh06_temp_hybrid():
    print("AFGH06Temp BENCHMARK")
    pre = AFGH06Temp(group_obj)
    hyb = HybridUniPREnc(pre)
    params = hyb.setup()
    (pk_a, sk_a) = hyb.keygen(params)
    (pk_b, sk_b) = hyb.keygen(params)
    msg = os.urandom(1000)

    assert group_obj.InitBenchmark(), "failed to initialize utils"
    c_a_1 = benchmark(lambda: hyb.encrypt_lvl1(params, pk_a, msg), "Encryption lvl1")
    c_a_2 = benchmark(lambda: hyb.encrypt_lvl2(params, pk_a, msg, l='2018'), "Encryption lvl2")
    rk = benchmark(lambda: hyb.re_keygen(params, sk_a, pk_b, l='2018'), "Proxy re-encryption key generation")
    c_b_1 = benchmark(lambda: hyb.re_encrypt(params, rk, c_a_2), "Re-encryption")
    msg2 = benchmark(lambda: hyb.decrypt_lvl1(params, sk_a, c_a_1), "Decryption lvl1")
    msg2 = benchmark(lambda: hyb.decrypt_lvl2(params, sk_a, c_a_2, l='2018'), "Decryption lvl2")
    msg2 = benchmark(lambda: hyb.decrypt_lvl1(params, sk_b, c_b_1), "Decryption of re-encrypted")


if __name__ == "__main__":
    benchmark_afgh06()
    # benchmark_afgh06_time()
    # benchmark_afgh06_temp()
    # benchmark_afgh06_hybrid()
    # benchmark_afgh06_time_hybrid()
    # benchmark_afgh06_temp_hybrid()

# from charm.schemes.abenc.abenc_waters09 import CPabe09
from charm.schemes.abenc.abenc_waters09_cca_jm import CPabe09CCA
from charm.schemes.abenc.abenc_waters09_jm import CPabe09
from charm.schemes.abenc.ac17 import AC17CPABE
from charm.toolbox.pairinggroup import PairingGroup, GT
import os

from charm.schemes.pksig.lamport_jm import Lamport

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
        string += k + ": " + str(round(v, 1)) + " us, "
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


def benchmark_waters11():
    global group_obj
    print("W11 BENCHMARK")
    group_obj = PairingGroup('SS512')
    scheme = CPabe09(group_obj)
    policy = '2018'
    msg = group_obj.random(GT)
    assert group_obj.InitBenchmark(), "failed to initialize utils"
    customer_a_msk, customer_a_mpk = benchmark(lambda: scheme.setup(), "Setup")
    sk_a_b = benchmark(lambda: scheme.keygen(customer_a_mpk, customer_a_msk, ['2018']), "Keygen")
    c = benchmark(lambda: scheme.encrypt(customer_a_mpk, msg, policy), "Encrypt")
    msg_prime = benchmark(lambda: scheme.decrypt(customer_a_mpk, sk_a_b, c), "Decrypt")
    assert msg == msg_prime


def benchmark_waters11_cca():
    global group_obj
    print("W11 CCA BENCHMARK")
    group_obj = PairingGroup('SS512')
    sig_obj = Lamport()
    scheme = CPabe09CCA(group_obj, sig_obj)
    policy = '2018'
    msg = group_obj.random(GT)
    assert group_obj.InitBenchmark(), "failed to initialize utils"
    customer_a_msk, customer_a_mpk = benchmark(lambda: scheme.setup(), "Setup")
    sk_a_b = benchmark(lambda: scheme.keygen(customer_a_mpk, customer_a_msk, ['2018']), "Keygen")
    c = benchmark(lambda: scheme.encrypt(customer_a_mpk, msg, policy), "Encrypt")
    msg_prime = benchmark(lambda: scheme.decrypt(customer_a_mpk, sk_a_b, c), "Decrypt")
    assert msg == msg_prime


def benchmark_ac17():
    global group_obj
    group_obj = PairingGroup('MNT224')
    print("ABENC BENCHMARK")
    scheme = AC17CPABE(group_obj, 2)
    # customer_a_msk, customer_a_mpk = scheme.setup()
    policy = '2018'
    # sk_a_b = scheme.keygen(customer_a_mpk, customer_a_msk, ['2018'])
    msg = group_obj.random(GT)
    # c = scheme.encrypt(customer_a_mpk, msg, policy)
    # msg_prime = scheme.decrypt(sk_a_b, c)

    assert group_obj.InitBenchmark(), "failed to initialize utils"

    customer_a_mpk, customer_a_msk = benchmark(lambda: scheme.setup(), "Setup")
    sk_a_b = benchmark(lambda: scheme.keygen(customer_a_mpk, customer_a_msk, ['2018']), "Keygen")
    c = benchmark(lambda: scheme.encrypt(customer_a_mpk, msg, policy), "Encrypt")
    msg_prime = benchmark(lambda: scheme.decrypt(customer_a_mpk, c, sk_a_b), "Decrypt")
    assert msg == msg_prime


if __name__ == "__main__":
    benchmark_waters11()
    benchmark_waters11_cca()
    # benchmark_ac17()

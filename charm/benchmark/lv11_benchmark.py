from charm.schemes.prenc.pre_lv11_jm import LV11
from charm.schemes.prenc.pre_lv11_time_jm import LV11Time
from charm.schemes.prenc.pre_lv11_temp_jm import LV11Temp
from charm.schemes.pksig.lamport_jm import Lamport
from charm.toolbox.pairinggroup import PairingGroup, GT

iterations = 100
bmFlags = ["RealTime", "CpuTime", "Div", "Mul", "Exp", "Pair", "Granular"]

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

def benchmark_lv11():
    print('LV11')
    groupObj = PairingGroup('SS512', verbose=True)
    sigObj = Lamport()
    pre = LV11(groupObj, sigObj, pre_compute=True)
    params = pre.setup()
    # Key generation
    (pk_a, sk_a) = pre.keygen(params)
    (pk_b, sk_b) = pre.keygen(params)
    # Message
    msg = groupObj.random(GT)

    assert groupObj.InitBenchmark(), "failed to initialize utils"

    # Encryption
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        c_a1 = pre.encrypt_lvl1(params, pk_a, msg)
    groupObj.EndBenchmark()
    enc1bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        c_a2 = pre.encrypt_lvl2(params, pk_a, msg)
    groupObj.EndBenchmark()
    enc2bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    # Re-encryption key generation
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        rk = pre.re_keygen(params, sk_a, pk_b)
    groupObj.EndBenchmark()
    rekeybm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    # Re-encryption
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        c_b = pre.re_encrypt(params, rk, c_a2, pk_i=pk_a)
    groupObj.EndBenchmark()
    reencbm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    # Decryption
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        dec_ca1 = pre.decrypt_lvl1(params, sk_a, c_a1, pk_i=pk_a)
    groupObj.EndBenchmark()
    dec1bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())
    assert msg == dec_ca1, "Msg: %s \n Dec: %s" % (msg, dec_ca1)  # PASS: ENC1 -> DEC1

    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        dec_cb = pre.decrypt_lvl1(params, sk_b, c_b, pk_i=pk_b)
    groupObj.EndBenchmark()
    decrebm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())
    assert msg == dec_cb, "Msg: %s \n Dec: %s" % (msg, dec_cb)  # PASS: ENC2 -> REENC -> DEC1

    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        dec_ca2 = pre.decrypt_lvl2(params, sk_a, c_a2, pk_i=pk_a)
    groupObj.EndBenchmark()
    dec2bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())
    assert msg == dec_ca2, "Msg: %s \n Dec: %s" % (msg, dec_ca2)  # PASS: ENC2 -> DEC2

    print_benchmark("Encryption, lvl 1 ", normbm(enc1bm, iterations))
    print_benchmark("Encryption, lvl 2 ", normbm(enc2bm, iterations))
    print_benchmark("Re-keygen", normbm(rekeybm, iterations))
    print_benchmark("Re-encryption", normbm(reencbm, iterations))
    print_benchmark("Decryption, lvl 1", normbm(dec1bm, iterations))
    print_benchmark("Decryption, lvl 1 re-encrypted", normbm(decrebm, iterations))
    print_benchmark("Decryption, lvl 2", normbm(dec2bm, iterations))
    print()

def benchmark_lv11_time():
    print('LV11 Time Property')
    groupObj = PairingGroup('SS512', verbose=True)
    sigObj = Lamport()
    pre = LV11Time(groupObj, sigObj, pre_compute=True)
    params = pre.setup()
    # Key generation
    (pk_a, sk_a) = pre.keygen(params)
    (pk_b, sk_b) = pre.keygen(params)
    # Message
    msg = groupObj.random(GT)
    ts_2018 = pre.sign_timestamp(sk_a, '2018')

    assert groupObj.InitBenchmark(), "failed to initialize utils"

    # Encryption
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        c_a1 = pre.encrypt_lvl1(params, pk_a, msg)
    groupObj.EndBenchmark()
    enc1bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        c_a2 = pre.encrypt_lvl2(params, pk_a, msg, signed_timestamp=ts_2018)
    groupObj.EndBenchmark()
    enc2bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    # Re-encryption key generation
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        rk_2018 = pre.re_keygen(params, sk_a, pk_b, signed_timestamp=ts_2018)
    groupObj.EndBenchmark()
    rekeybm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    # Re-encryption
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        c_b = pre.re_encrypt(params, rk_2018, c_a2, pk_i=pk_a)
    groupObj.EndBenchmark()
    reencbm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    # Decryption
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        dec_ca1 = pre.decrypt_lvl1(params, sk_a, c_a1, pk_i=pk_a)
    groupObj.EndBenchmark()
    dec1bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())
    assert msg == dec_ca1, "Msg: %s \n Dec: %s" % (msg, dec_ca1)  # PASS: ENC1 -> DEC1

    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        dec_cb = pre.decrypt_lvl1(params, sk_b, c_b, pk_i=pk_b)
    groupObj.EndBenchmark()
    decrebm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())
    assert msg == dec_cb, "Msg: %s \n Dec: %s" % (msg, dec_cb)  # PASS: ENC2 -> REENC -> DEC1

    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        dec_ca2 = pre.decrypt_lvl2(params, sk_a, c_a2, pk_i=pk_a)
    groupObj.EndBenchmark()
    dec2bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())
    assert msg == dec_ca2, "Msg: %s \n Dec: %s" % (msg, dec_ca2)  # PASS: ENC2 -> DEC2

    print_benchmark("Encryption, lvl 1 ", normbm(enc1bm, iterations))
    print_benchmark("Encryption, lvl 2 ", normbm(enc2bm, iterations))
    print_benchmark("Re-keygen", normbm(rekeybm, iterations))
    print_benchmark("Re-encryption", normbm(reencbm, iterations))
    print_benchmark("Decryption, lvl 1", normbm(dec1bm, iterations))
    print_benchmark("Decryption, lvl 1 re-encrypted", normbm(decrebm, iterations))
    print_benchmark("Decryption, lvl 2", normbm(dec2bm, iterations))
    print()

def benchmark_lv11_temp():
    print('LV11 Temporary Delegation')
    groupObj = PairingGroup('SS512', verbose=True)
    sigObj = Lamport()
    pre = LV11Temp(groupObj, sigObj, pre_compute=True)
    params = pre.setup()
    # Key generation
    (pk_a, sk_a) = pre.keygen(params)
    (pk_b, sk_b) = pre.keygen(params)
    # Message
    msg = groupObj.random(GT)

    assert groupObj.InitBenchmark(), "failed to initialize utils"

    # Encryption
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        c_a1 = pre.encrypt_lvl1(params, pk_a, msg, l='2018')
    groupObj.EndBenchmark()
    enc1bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        c_a2 = pre.encrypt_lvl2(params, pk_a, msg, l='2018')
    groupObj.EndBenchmark()
    enc2bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    # Re-encryption key generation
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        rk = pre.re_keygen(params, pk_b, sk_a, l='2018', pk_a=pk_a)
    groupObj.EndBenchmark()
    rekeybm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    # Re-encryption
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        c_b = pre.re_encrypt(params, rk, c_a2, pk_i=pk_a, l='2018', pk_a=pk_a)
    groupObj.EndBenchmark()
    reencbm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    # Decryption
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        dec_ca1 = pre.decrypt_lvl1(params, sk_a, c_a1, pk_b=pk_a)
    groupObj.EndBenchmark()
    dec1bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())
    assert msg == dec_ca1, "Msg: %s \n Dec: %s" % (msg, dec_ca1)  # PASS: ENC1 -> DEC1

    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        dec_cb = pre.decrypt_lvl1(params, sk_b, c_b, pk_b=pk_b)
    groupObj.EndBenchmark()
    decrebm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())
    assert msg == dec_cb, "Msg: %s \n Dec: %s" % (msg, dec_cb)  # PASS: ENC2 -> REENC -> DEC1

    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        dec_ca2 = pre.decrypt_lvl2(params, sk_a, c_a2, pk_a=pk_a)
    groupObj.EndBenchmark()
    dec2bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())
    assert msg == dec_ca2, "Msg: %s \n Dec: %s" % (msg, dec_ca2)  # PASS: ENC2 -> DEC2

    print_benchmark("Encryption, lvl 1 ", normbm(enc1bm, iterations))
    print_benchmark("Encryption, lvl 2 ", normbm(enc2bm, iterations))
    print_benchmark("Re-keygen", normbm(rekeybm, iterations))
    print_benchmark("Re-encryption", normbm(reencbm, iterations))
    print_benchmark("Decryption, lvl 1", normbm(dec1bm, iterations))
    print_benchmark("Decryption, lvl 1 re-encrypted", normbm(decrebm, iterations))
    print_benchmark("Decryption, lvl 2", normbm(dec2bm, iterations))
    print()

def benchmark_lv11_hybrid():
    from pre.adapters.pre_hybrid import HybridUniPREnc
    import os
    print('LV11 hybrid')
    groupObj = PairingGroup('SS512', verbose=True)
    sigObj = Lamport()
    pre = LV11(groupObj, sigObj)
    hyb = HybridUniPREnc(pre)
    params = hyb.setup()
    # Key generation
    (pk_a, sk_a) = hyb.keygen(params)
    (pk_b, sk_b) = hyb.keygen(params)
    # Message
    msg = os.urandom(1000 * 1)

    assert groupObj.InitBenchmark(), "failed to initialize utils"

    # Encryption
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        c_a1 = hyb.encrypt_lvl1(params, pk_a, msg)
    groupObj.EndBenchmark()
    enc1bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        c_a2 = hyb.encrypt_lvl2(params, pk_a, msg)
    groupObj.EndBenchmark()
    enc2bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    # Re-encryption key generation
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        rk = hyb.re_keygen(params, pk_b, sk_a)
    groupObj.EndBenchmark()
    rekeybm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    # Re-encryption
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        c_b = hyb.re_encrypt(params, rk, c_a2, pk_i=pk_a)
    groupObj.EndBenchmark()
    reencbm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())

    # Decryption
    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        dec_ca1 = hyb.decrypt_lvl1(params, sk_a, c_a1, pk_i=pk_a)
    groupObj.EndBenchmark()
    dec1bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())
    assert msg == dec_ca1, "Msg: %s \n Dec: %s" % (msg, dec_ca1)  # PASS: ENC1 -> DEC1

    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        dec_cb = hyb.decrypt_lvl1(params, sk_b, c_b, pk_i=pk_b)
    groupObj.EndBenchmark()
    decrebm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())
    assert msg == dec_cb, "Msg: %s \n Dec: %s" % (msg, dec_cb)  # PASS: ENC2 -> REENC -> DEC1

    groupObj.StartBenchmark(bmFlags)
    for i in range(iterations):
        dec_ca2 = hyb.decrypt_lvl2(params, sk_a, c_a2, pk_i=pk_a)
    groupObj.EndBenchmark()
    dec2bm = (groupObj.GetGeneralBenchmarks(), groupObj.GetGranularBenchmarks())
    assert msg == dec_ca2, "Msg: %s \n Dec: %s" % (msg, dec_ca2)  # PASS: ENC2 -> DEC2

    print_benchmark("Encryption, lvl 1 ", normbm(enc1bm, iterations))
    print_benchmark("Encryption, lvl 2 ", normbm(enc2bm, iterations))
    print_benchmark("Re-keygen", normbm(rekeybm, iterations))
    print_benchmark("Re-encryption", normbm(reencbm, iterations))
    print_benchmark("Decryption, lvl 1", normbm(dec1bm, iterations))
    print_benchmark("Decryption, lvl 1 re-encrypted", normbm(decrebm, iterations))
    print_benchmark("Decryption, lvl 2", normbm(dec2bm, iterations))
    print()


if __name__ == "__main__":
    # benchmark_lv11()
    # benchmark_lv11_time()
    benchmark_lv11_temp()
    # benchmark_lv11_hybrid()

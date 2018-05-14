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


def benchmark(func, title, group, iterations=100, bm_flags=None):
    if bm_flags is None:
        bm_flags = ["RealTime", "CpuTime", "Div", "Mul", "Exp", "Pair", "Granular"]
    ret = None
    group.StartBenchmark(bm_flags)
    for i in range(iterations):
        ret = func()
    group.EndBenchmark()
    bm = (group.GetGeneralBenchmarks(), group.GetGranularBenchmarks())
    print_benchmark(title, normbm(bm, iterations))
    return ret
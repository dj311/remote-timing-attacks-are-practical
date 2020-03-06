import sympy


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

    return bytes(bys)


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

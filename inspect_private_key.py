import argparse
import tlslite
import sympy
import code


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("certificate", type=argparse.FileType("r"))

    args = parser.parse_args()

    with args.certificate as file:
        certificate = file.read()

    private_key = tlslite.utils.python_rsakey.Python_RSAKey.parsePEM(certificate)

    print("p =", private_key.p)
    print("q =", private_key.q)
    print("N =", private_key.n)

    p = sympy.Integer(private_key.p)
    q = sympy.Integer(private_key.q)
    N = sympy.Integer(private_key.n)

    code.interact(local=locals())

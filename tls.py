import code
import io
import secrets
import socket
import rdtsc

from collections import namedtuple
from tlslite.x509 import X509

from ctypes import *
from tlslite.constants import *


TLS_VERSION_1_0 = 769

# lazy
X509_CERT_TYPE_EXTENSION = int.from_bytes(
    bytes.fromhex("000900020100"), byteorder="big"
)

HELLO_CIPHER_SUITE_SIZE = 2
HELLO_CIPHER_SUITE_LENGTH_SIZE = 2
HELLO_COMPRESSION_METHOD_SIZE = 1
HELLO_COMPRESSION_METHOD_LENGTH_SIZE = 1
HELLO_EXTENSION_SIZE = 6
HELLO_EXTENSION_LENGTH_SIZE = 2


def recvall(sock):
    all_data = []

    data = sock.recv(4096)
    all_data.append(data)

    try:
        while True:
            data = sock.recv(4096, socket.MSG_DONTWAIT)
            all_data.append(data)

    except io.BlockingIOError:
        pass  #  no more data to recieve

    finally:
        return b"".join(all_data)


def encode_list_to_bytes(items, item_size, length_size):
    length = len(items) * item_size
    raw_length = length.to_bytes(length_size, byteorder="big")
    raw_items = b"".join([item.to_bytes(item_size, byteorder="big") for item in items])
    return raw_length + raw_items


def decode_list_from_bytes(raw, item_size, length_size):
    length = int.from_bytes(raw[0:length_size], byteorder="big")
    start = length_size
    items = [
        int.from_bytes(raw[start : start + item_size], byteorder="big")
        for i in range(start, start + length, item_size)
    ]
    return items, length


class Alert(namedtuple("Alert", ["level", "description"])):
    def to_bytes(self):
        raw_level = self.level.to_bytes(1, byteorder="big")
        raw_description = self.description.to_bytes(1, byteorder="big")

        return raw_level + raw_description

    @classmethod
    def from_bytes(cls, raw):
        level = int.from_bytes(raw_header[0], byteorder="big")
        description = int.from_bytes(raw_header[1], byteorder="big")

        return cls(level, description)


class HandshakeFinished(namedtuple("HandshakeFinished", [])):
    def to_bytes(self):
        return bytes([0x01])

    @classmethod
    def from_bytes(cls, raw):
        if raw == bytes([0x01]):
            return cls()
        else:
            return False


class ChangeCipherSpec(namedtuple("ChangeCipherSpec", [])):
    def to_bytes(self):
        return bytes([0x01])

    @classmethod
    def from_bytes(cls, raw):
        if raw == bytes([0x01]):
            return cls()
        else:
            return False


class ClientKeyExchange(namedtuple("ClientKeyExchange", ["enc_premaster_secret"])):
    def to_bytes(self):
        raw_length = int.to_bytes(128, 2, byteorder="big")
        raw_enc_premaster_secret = self.enc_premaster_secret.to_bytes(
            128, byteorder="big"
        )
        return raw_length + raw_enc_premaster_secret

    @classmethod
    def from_bytes(cls, raw):
        return cls(bytes(raw[2:]))


class ServerHelloDone(namedtuple("ServerHelloDone", [])):
    def to_bytes(self):
        return b""

    @classmethod
    def from_bytes(cls, raw):
        return cls()


class Certificate(namedtuple("Certificate", ["certificates"])):
    @classmethod
    def from_bytes(cls, raw):
        length = int.from_bytes(raw[0:3], byteorder="big")

        certs_start = 3
        certs_end = 3 + length

        certs = []

        offset = certs_start
        while offset < certs_end:
            cert_length = int.from_bytes(raw[offset : offset + 3], byteorder="big")
            offset += 3

            raw_cert = bytes(raw[offset : offset + cert_length])
            offset += cert_length

            cert = X509()
            cert.parseBinary(raw_cert)

            certs.append(cert)

        return cls(certs)


class ServerHello(
    namedtuple(
        "ServerHello",
        [
            "version",
            "timestamp",
            "random_bytes",
            "session_id",
            "cipher_suite",
            "compression_method",
        ],
    )
):
    @classmethod
    def from_bytes(cls, raw):
        offset = 0

        version = int.from_bytes(raw[0:2], byteorder="big")
        offset += 2

        timestamp = int.from_bytes(raw[offset : offset + 4], byteorder="big")
        offset += 4

        random = bytes(raw[offset : offset + 28])
        offset += 28

        session_id_length = int.from_bytes(raw[offset : offset + 1], byteorder="big")
        offset += 1

        session_id = bytes(raw[offset : offset + session_id_length])
        offset += session_id_length

        cipher_suite = int.from_bytes(
            raw[offset : offset + HELLO_CIPHER_SUITE_SIZE], byteorder="big"
        )
        offset += HELLO_CIPHER_SUITE_SIZE

        compression_method = int.from_bytes(
            raw[offset : offset + HELLO_COMPRESSION_METHOD_SIZE], byteorder="big"
        )
        offset += HELLO_COMPRESSION_METHOD_SIZE

        return cls(
            version, timestamp, random, session_id, cipher_suite, compression_method
        )


class ClientHello(
    namedtuple(
        "ClientHello",
        [
            "version",
            "timestamp",
            "random_bytes",
            "session_id",
            "cipher_suites",
            "compression_methods",
            "extensions",
        ],
    )
):
    def to_bytes(self):
        raw_version = self.version.to_bytes(2, byteorder="big")

        raw_timestamp = self.timestamp.to_bytes(4, byteorder="big")
        raw_random = self.random_bytes

        session_id_length = len(self.session_id)
        raw_session_id_length = session_id_length.to_bytes(1, byteorder="big")
        raw_session_id = self.session_id

        raw_cipher_suites = encode_list_to_bytes(
            self.cipher_suites, HELLO_CIPHER_SUITE_SIZE, HELLO_CIPHER_SUITE_LENGTH_SIZE
        )
        raw_compression_methods = encode_list_to_bytes(
            self.compression_methods,
            HELLO_COMPRESSION_METHOD_SIZE,
            HELLO_COMPRESSION_METHOD_LENGTH_SIZE,
        )
        raw_extensions = encode_list_to_bytes(
            self.extensions, HELLO_EXTENSION_SIZE, HELLO_EXTENSION_LENGTH_SIZE
        )

        return b"".join(
            [
                raw_version,
                raw_timestamp,
                raw_random,
                raw_session_id_length,
                raw_session_id,
                raw_cipher_suites,
                raw_compression_methods,
                raw_extensions,
            ]
        )


class Handshake(namedtuple("Handshake", ["handshake_type", "body"])):
    def to_bytes(self):
        raw_type = self.handshake_type.to_bytes(1, byteorder="big")
        raw_body = self.body.to_bytes()

        raw_length = len(raw_body).to_bytes(3, byteorder="big")

        return raw_type + raw_length + raw_body

    @classmethod
    def from_bytes(cls, raw):
        raw_header, raw_body = raw[0:4], raw[4:]

        handshake_type = int.from_bytes(raw_header[0:1], byteorder="big")
        length = int.from_bytes(raw_header[1:4], byteorder="big")

        body = {
            HandshakeType.client_hello: ClientHello,
            HandshakeType.server_hello: ServerHello,
            HandshakeType.server_hello_done: ServerHelloDone,
            HandshakeType.certificate: Certificate,
        }[handshake_type].from_bytes(raw_body[0:length])

        return cls(handshake_type, body)


class Record(namedtuple("Record", ["content_type", "version", "body", "raw"])):
    def to_bytes(self):
        raw_content_type = self.content_type.to_bytes(1, byteorder="big")
        raw_version = self.version.to_bytes(2, byteorder="big")
        raw_body = self.body.to_bytes()
        raw_length = len(raw_body).to_bytes(2, byteorder="big")

        return raw_content_type + raw_version + raw_length + raw_body

    @classmethod
    def from_bytes(cls, raw):
        raw_header, raw_body = raw[0:5], raw[5:]

        content_type = int.from_bytes(raw_header[0:1], byteorder="big")
        version = int.from_bytes(raw_header[1:3], byteorder="big")
        length = int.from_bytes(raw_header[3:5], byteorder="big")

        body = {
            ContentType.alert: Alert,
            ContentType.handshake: Handshake,
            # ContentType.application_data: ApplicationData,
            # ContentType.change_cipher_spec: ChangeCipherSpec,
        }[content_type].from_bytes(raw_body[0:length])

        return cls(content_type, version, body, raw[0 : 5 + length])


if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("antelope", 443))

    client_hello = Record(
        ContentType.handshake,
        TLS_VERSION_1_0,
        Handshake(
            HandshakeType.client_hello,
            ClientHello(
                TLS_VERSION_1_0,
                2451205766,
                secrets.token_bytes(28),
                b"",
                [CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA],
                [0],
                [X509_CERT_TYPE_EXTENSION],
            ),
        ),
        None,
    )
    sock.send(client_hello.to_bytes())

    response = recvall(sock)

    server_hello = Record.from_bytes(response)
    response = response[len(server_hello.raw) :]

    certificates = Record.from_bytes(response)
    response = response[len(certificates.raw) :]

    server_hello_done = Record.from_bytes(response)
    response = response[len(server_hello_done.raw) :]

    client_key_exchange = Record(
        ContentType.handshake,
        TLS_VERSION_1_0,
        Handshake(HandshakeType.client_key_exchange, ClientKeyExchange(0)),
        None,
    )
    change_cipher_spec = Record(
        ContentType.change_cipher_spec, TLS_VERSION_1_0, ChangeCipherSpec()
    )
    encrypted_handshake = Record(ContentType.handshake, TLS_VERSION_1_0)
    combined_message = (
        client_key_exchange.to_bytes()
        + change_cipher_spec.to_bytes()
        + encrypted_handshake.to_bytes()
    )

    start_time = rdtsc.get_cycles()
    sock.send(combined_message)
    response = recvall(sock)
    end_time = rdtsc.get_cycles()

    code.interact(local=locals())

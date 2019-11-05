import code
import io
import secrets
import socket

from collections import namedtuple
from tlslite.x509 import X509

from ctypes import *
from tlslite.constants import *


class TLSExtensionCertificateType(EasyStructure):
    _fields_ = [
        ("type", 2 * c_ubyte),
        ("length", 2 * c_uint8),
        ("type_list_length", c_uint8),
        ("type_list", c_ubyte),
    ]


class TLSHandshakeHeader(EasyStructure):
    _fields_ = [("handshake_type", c_uint8), ("length", 3 * c_uint8)]


class TLSHandshakeClientHello(TLSHandshakeContents):
    content_type = ContentType.handshake
    handshake_type = HandshakeType.client_hello
    _fields_ = [
        ("version", 2 * c_uint8),
        ("timestamp", 4 * c_uint8),
        ("random_bytes", 28 * c_ubyte),
        # Doesn't support session ids:
        ("session_id_length", c_uint8),  # == 0
        # Only allow 1 cipher suite, so next field is 2 bytes
        ("cipher_suites_length", 2 * c_uint8),  # == 2
        ("cipher_suites", 2 * c_uint8),
        # Only allow one compression method: null
        ("compression_methods_length", c_uint8),  # == 1
        ("compression_methods", c_uint8),  # == null == 0x00
        # Copy and paste these bytes from a pcap
        ("extensions_length", 2 * c_uint8),  # == 6
        ("extensions", TLSExtensionCertificateType),
    ]

    def __init__(self, *args, **kwargs):
        # Force constant values
        kwargs["session_id_length"] = 0
        kwargs["cipher_suites_length"] = 2
        kwargs["compression_methods_length"] = 1
        kwargs["compression_methods"] = 0
        kwargs["extensions_length"] = 6

        return super().__init__(*args, **kwargs)


class TLSHandshakeCertificate(TLSHandshakeContents):
    content_type = ContentType.handshake
    handshake_type = HandshakeType.certificate

    @classmethod
    def from_cert(cls, cert_bytes):
        length = len(cert_bytes)

        class TLSHandshakeCertificateFromBytes(cls):
            _fields_ = [("length", 2 * c_uint8), ("certificate", length * c_ubyte)]

        return TLSHandshakeCertificateFromBytes(length=length, certificate=cert_bytes)


class TLSHandshakeServerHelloDone(TLSHandshakeContents):
    content_type = ContentType.handshake
    handshake_type = HandshakeType.server_hello_done

    _fields_ = [
        # Empty, only need handshake header
    ]


class TLSHandshakeClientKeyExchange(TLSHandshakeContents):
    content_type = ContentType.handshake
    handshake_type = HandshakeType.client_key_exchange

    @classmethod
    def from_bytes(encrypted_premaster_secret):
        length = len(encrypted_premaster_secret)

        class TLSHandshakeClientKeyExchangeFromBytes(TLSHandshakeClientKeyExchange):
            _fields_ = [
                ("length", 2 * c_uint8),
                ("enc_premaster_secret", length * c_ubyte),
            ]

        return TLSHandshakeClientKeyExchangeFromBytes(
            length=length, enc_premaster_secret=encrypted_premaster_secret
        )


class TLSHandshakeChangeCipherSpec(TLSHandshakeContents):
    content_type = ContentType.change_cipher_spec
    _fields_ = [("message_type", c_ubyte)]

    def __init__(self, *args, **kwargs):
        kwargs["message_type"] = 0x01
        return super().__init__(*args, **kwargs)


class TLSHandshakeEncryptedMessage(TLSHandshakeContents):
    content_type = ContentType.handshake

    @classmethod
    def from_bytes(encrypted_message):
        length = len(encrypted_message)

        class TLSHandshakeEncryptedMessageFromBytes(TLSHandshakeEncryptedMessage):
            _fields_ = [("enc_message", length * c_ubyte)]

        return TLSHandshakeEncryptedMessageFromBytes(
            length=length, enc_message=encrypted_message
        )


def create_tls_alert(alert_message):
    raw_alert_message = bytes(alert_message)
    message_length = len(raw_alert_message)

    tls_header = TLSHeader(
        content_type=ContentType.alert, version=0x0303, length=message_length
    )
    raw_tls_header = bytes(tls_header)
    header_length = len(raw_tls_header)

    return create_string_buffer(raw_tls_header + raw_alert_message)


def create_tls_handshake(handshake_message):
    raw_handshake_message = bytes(handshake_message)
    message_length = len(raw_handshake_message)

    handshake_header = TLSHandshakeHeader(
        handshake_type=handshake_message.handshake_type, length=message_length
    )
    raw_handshake_header = bytes(handshake_header)
    handshake_header_length = len(raw_handshake_header)

    tls_header = TLSHeader(
        content_type=ContentType.handshake,
        version=(0x03, 0x03),
        length=handshake_header_length + message_length,
    )
    raw_tls_header = bytes(tls_header)
    tls_header_length = len(raw_tls_header)

    return create_string_buffer(
        raw_tls_header + raw_handshake_header + raw_handshake_message
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

        return cls(level, description), b""


class ServerHelloDone(namedtuple("ServerHelloDone", [])):
    def to_bytes(self):
        return b""

    @classmethod
    def from_bytes(cls, raw):
        return cls(), b""


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

            cert = tlslite.x509.X509()
            cert.parseBinary(raw_cert)

            certs.append(cert)

        return cls(certs), b""


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

        return (
            cls(
                version, timestamp, random, session_id, cipher_suite, compression_method
            ),
            b"",
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

        raw_cipher_suites = self.encode_list_to_bytes(
            self.cipher_suites, HELLO_CIPHER_SUITE_SIZE, HELLO_CIPHER_SUITE_LENGTH_SIZE
        )
        raw_compression_methods = self.encode_list_to_bytes(
            self.compression_methods,
            HELLO_COMPRESSION_METHOD_SIZE,
            HELLO_COMPRESSION_METHOD_LENGTH_SIZE,
        )
        raw_extensions = self.encode_list_to_bytes(
            self.extensions, HELLO_EXTENSION_SIZE, HELLO_EXTENSION_LENGTH_SIZE
        )

        return b"".join(
            [
                raw_version,
                raw_timestamp,
                raw_random,
                raw_cipher_suites,
                raw_compression_methods,
                raw_extensions,
            ]
        )


class HandshakeHeader(namedtuple("HandshakeHeader", ["handshake_type", "length"])):
    def to_bytes(self):
        raw_type = self.handshake_type.to_bytes(1, byteorder="big")
        raw_length = self.length.to_bytes(3, byteorder="big")

        return raw_type + raw_length

    @classmethod
    def from_bytes(cls, raw_header):
        handshake_type = raw_header[0].from_bytes(byteorder="big")
        length = raw_header[1:4].from_bytes(byteorder="big")

        return cls(handshake_type, length), b""


class Handshake(namedtuple("Handshake", ["header", "body"])):
    def to_bytes(self):
        raw_header = self.header.to_bytes()
        raw_message = self.message.to_bytes()

        return raw_header + raw_message

    @classmethod
    def from_bytes(cls, raw_handshake):
        header, raw_body = HandshakeHeader.from_bytes(raw_handshake)

        body = {
            HandshakeType.client_hello: ClientHello,
            HandshakeType.server_hello: ServerHello,
            HandshakeType.server_hello_done: ServerHelloDone,
            HandshakeType.certificate: Certificate,
        }[header.handshake_type].from_bytes(raw_body[0 : header.length])

        return cls(header, body), b""


class TLSHeader(namedtuple("TLSHeader", ["content_type", "version", "length"])):
    def to_bytes(self):
        raw_content_type = self.content_type.to_bytes(1, byteorder="big")
        raw_version = self.version.to_bytes(2, byteorder="big")
        raw_length = self.length.to_bytes(2, byteorder="big")

        return raw_content_type + raw_version + raw_length

    @classmethod
    def from_bytes(cls, raw_message):
        content_type = int.from_bytes(raw_message[0], byteorder="big")
        version = int.from_bytes(raw_message[1:3], byteorder="big")
        length = int.from_bytes(raw_message[3:5], byteorder="big")

        return cls(content_type, version, length), raw_message[5:], b""


class TLSRecord(namedtuple("TLSRecord", ["header", "body"])):
    def to_bytes(self):
        raw_header = self.header.to_bytes()
        raw_body = self.body.to_bytes()

        return raw_header + raw_body

    @classmethod
    def from_bytes(cls, raw_record):
        header, raw_body = TLSHeader.from_bytes(raw_record)

        body = {
            ContentType.handshake: Handshake,
            ContentType.application_data: ApplicationData,
            ContentType.change_cipher_spec: ChangeCipherSpec,
            ContentType.alert: Alert,
        }[header.content_type].from_bytes(raw_body[0 : header.length])

        leftovers = raw_body[header.length :]

        return cls(header, body), leftovers


if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("antelope", 443))

    # create and send client hello
    client_hello = create_tls_handshake(
        TLSHandshakeClientHello(
            version=(0x03, 0x03),
            timestamp=2451205766,
            random_bytes=secrets.token_bytes(28),
            cipher_suites=CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            extensions=TLSExtensionCertificateType(
                ExtensionType.cert_type, 2, 1, CertificateType.x509
            ),
        )
    )
    sock.send(client_hello)

    # read and parse response: should have three messages
    response = recvall(sock)

    offset = 0

    server_hello = TLSHandshakeServerHello.from_buffer_copy(response[offset:])
    server_hello_length = len(bytes(server_hello))
    offset += server_hello_length

    cert_length = int.from_bytes(response[offset : offset + 2], byteorder="big")
    server_cert = TLSHandshakeCertificate.from_cert(
        response[offset : offset + cert_length]
    )
    offset += cert_length

    server_hello_done = TLSHandshakeServerHelloDone.from_buffer_copy(response[offset:])

    # send clientkeyexchange

    code.interact(local=locals())

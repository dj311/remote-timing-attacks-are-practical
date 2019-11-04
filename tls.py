from ctypes import *
from tlslite.constants import *


class TLSHeader(Structure):
    _fields_ = [
        ("content_type", c_uint, 1 * 8),
        ("version", c_uint, 2 * 8),
        ("length", c_uint, 2 * 8),
    ]


class TLSAlert(Structure):
    _fields_ = [("level", c_uint, 1 * 8), ("description", c_uint, 1 * 8)]


class TLSHandshakeHeader(Structure):
    _fields_ = [("handshake_type", c_uint, 8), ("length", c_uint, 3 * 8)]


class TLSHandshakeClientHello(Structure):
    _fields_ = [
        ("version", c_uint, 2 * 8),
        ("random_timestamp", c_uint, 4 * 8),
        ("random_bytes", c_ubytes, 28 * 8),
        # Doesn't support session ids:
        ("session_id_length", c_unit, 1 * 8),
        # Only allow 1 cipher suite, so next field is 2 bytes
        ("cipher_suites_length", c_unit, 2 * 8),
        ("cipher_suites", c_unit, 2 * 8),
        # Only allow one compression method: null
        ("compression_methods_length", c_unit, 1 * 8),
        ("compression_methods", c_unit, 1 * 8),
        # Copy and paste these bytes from a pcap
        ("extensions_length", c_unit, 2 * 8),
        ("extensions", c_unit, 10 * 8),
    ]


class TLSHandshakeServerHello(Structure):
    _fields_ = [
        # TODO
    ]


class TLSHandshakeCertificate(Structure):
    _fields_ = [
        # TODO
    ]


class TLSHandshakeServerHelloDone(Structure):
    _fields_ = [
        # TODO
    ]


class TLSHandshakeClientKeyExchange(Structure):
    _fields_ = [
        # TODO
    ]


class TLSHandshakeChangeCipherSpec(Structure):
    _fields_ = [
        # TODO
    ]


class TLSHandshakeEncryptedMessage(Structure):
    _fields_ = [
        # TODO
    ]

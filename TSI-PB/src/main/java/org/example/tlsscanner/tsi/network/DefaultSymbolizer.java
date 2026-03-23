package org.example.tlsscanner.tsi.network;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;

public class DefaultSymbolizer extends Symbolizer {
    @Override
    protected String parseServerHello(ServerHelloMessage serverHelloMessage) {
        return "SERVER_HELLO";
    }

    @Override
    protected String parseServerKeyExchange(ServerKeyExchangeMessage serverKeyExchangeMessage) {
        // The ServerKeyExchange message must be ignored to facilitate comparison
        // between hosts using different key exchange algorithms
        return "";
    }

    @Override
    protected String parseCertificateRequest(CertificateRequestMessage certificateRequestMessage) {
        // The CertificateRequest message must be ignored to facilitate comparison
        // between hosts with different client authentication requirements
        return "";
    }
}

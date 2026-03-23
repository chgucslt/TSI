package org.example.tlsscanner.tsi.network;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import org.example.tlsscanner.common.HexConverter;


import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class PreflightSymbolizer extends Symbolizer{

    @Override
    protected String parseServerKeyExchange(ServerKeyExchangeMessage message) {
        StringBuilder res = new StringBuilder("ECDHEServerKeyExchange:");
        if (message.getLength() != null && message.getLength().getValue() != null) {
            res.append(message.getLength().getValue());
        } else {
            res.append("null");
        }
        return res.toString();
    }

    @Override
    protected String parseCertificateRequest(CertificateRequestMessage message) {
        StringBuilder outputSymbol = new StringBuilder("CertificateRequest:");
        if (message.getSignatureHashAlgorithms() != null &&
                message.getSignatureHashAlgorithms().getValue() != null) {
            try {
                List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(
                        message.getSignatureHashAlgorithms().getValue()
                );
                List<String> algoAndHashString = new ArrayList<>();
                for (SignatureAndHashAlgorithm algo : signatureAndHashAlgorithms) {
                    algoAndHashString.add(HexConverter.bytesToHex(algo.getByteValue()));
                }
                algoAndHashString.sort(Comparator.naturalOrder());
                for (String algo : algoAndHashString) {
                    outputSymbol.append(algo).append("_");
                }
            } catch (Exception var5) {
                System.err.println("Error: Parse SignatureAndHashAlgorithms in CertificateRequest.");
            }
        } else {
            outputSymbol.append("null").append("_");
        }
        return outputSymbol.substring(0, outputSymbol.length() - 1);
    }

    @Override
    protected String parseServerHello(ServerHelloMessage message) {
        StringBuilder outputSymbol = new StringBuilder();

        outputSymbol.append("Version:");
        if (message.getProtocolVersion() != null) {
            outputSymbol.append(ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue()));
        } else {
            outputSymbol.append("null");
        }

        outputSymbol.append("$" + "CipherSuite:");
        if (message.getSelectedCipherSuite() != null && message.getSelectedCipherSuite().getValue() != null) {
            outputSymbol.append(HexConverter.bytesToHex(message.getSelectedCipherSuite().getValue()));
        } else {
            outputSymbol.append("null");
        }


        String renegotiation = "$" + "Renegotiation:null";
        String heartbeat = "$" + "Heartbeat:False";
        String ECPointFormats = "$" + "ECPointFormats:";
        if (message.getExtensions() != null) {
            for (ExtensionMessage e : message.getExtensions()) {
                // if it's some special Extension (such as Heartbeat), append the content of it, else append the length
                if (ExtensionType.getExtensionType(e.getExtensionType().getValue()) == ExtensionType.HEARTBEAT) {
                    heartbeat = "$" + "Heartbeat:True";
                } else if (ExtensionType.getExtensionType(e.getExtensionType().getValue()) == ExtensionType.RENEGOTIATION_INFO) {
                    renegotiation = "$" + "Renegotiation:" + HexConverter.bytesToHex(e.getExtensionType().getValue())
                            + "_" + e.getExtensionLength().getValue();
                } else if (ExtensionType.getExtensionType(e.getExtensionType().getValue()) == ExtensionType.EC_POINT_FORMATS) {
                    ECPointFormats = "$" + "ECPointFormats:" + HexConverter.bytesToHex(e.getExtensionType().getValue())
                            + "_" + HexConverter.bytesToHex(e.getExtensionBytes().getValue());
                }
            }
        }
        outputSymbol.append(renegotiation);
//        outputSymbol.append(heartbeat);
        outputSymbol.append(ECPointFormats);

        return outputSymbol.toString();
    }
}

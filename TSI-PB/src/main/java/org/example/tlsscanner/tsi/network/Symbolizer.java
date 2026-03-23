package org.example.tlsscanner.tsi.network;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import org.example.tlsscanner.common.HexConverter;

import java.util.List;


public abstract class Symbolizer {

    public String symbolize(TlsMessage message) {
        String label;
        switch (message.getProtocolMessageType()) {
            case UNKNOWN:
                label = "UNKNOWN";
                break;
            case ALERT:
                AlertMessage alertMessage = (AlertMessage) message;
                label = parseAlertProtocol(alertMessage);
                break;
            case HANDSHAKE:
                HandshakeMessage handshakeMessage = (HandshakeMessage) message;
                label = parseHandshakeProtocol(handshakeMessage);
                break;
            case CHANGE_CIPHER_SPEC:
                label = "CHANGE_CIPHER_SPEC";
                break;
            case APPLICATION_DATA:
                label = "APPLICATION_DATA";
                break;
            case HEARTBEAT:
                HeartbeatMessage heartbeatMessage = (HeartbeatMessage) message;
                label = parseHeartbeatProtocol(heartbeatMessage);
                break;
            default:
                label = message.toCompactString();
                break;
        }
        return label;
    }

    protected String parseHandshakeProtocol(HandshakeMessage handshakeMessage) {
        switch (handshakeMessage.getHandshakeMessageType()) {
            case UNKNOWN:
                return "HANDSHAKE_UNKNOWN";
            case SERVER_HELLO:
                return parseServerHello((ServerHelloMessage) handshakeMessage);
            case CERTIFICATE_REQUEST:
                return parseCertificateRequest((CertificateRequestMessage) handshakeMessage);
            case SERVER_KEY_EXCHANGE:
                return parseServerKeyExchange((ServerKeyExchangeMessage) handshakeMessage);
            case NEW_SESSION_TICKET:
                return parseNewSessionTicket((NewSessionTicketMessage) handshakeMessage);
            default:
                return handshakeMessage.toCompactString();
        }
    }

    protected String parseAlertProtocol(AlertMessage alertMessage) {
        String parseResult;
        AlertLevel level = AlertLevel.getAlertLevel(alertMessage.getLevel().getValue());
        AlertDescription description = AlertDescription.getAlertDescription(alertMessage.getDescription().getValue());
        parseResult = "ALERT_" + level.name() + "_";
        if (description == null) {
            parseResult += "UNKNOWN";
        } else {
            parseResult += description.name();
        }
        return parseResult;
    }

    protected String parseServerHello(ServerHelloMessage serverHelloMessage) {
        StringBuilder res = new StringBuilder("SERVER_HELLO_");

        if (serverHelloMessage.getProtocolVersion() != null) {
            res.append(ProtocolVersion.getProtocolVersion(serverHelloMessage.getProtocolVersion().getValue())).append("_");
        } else {
            res.append("null").append("_");
        }

        if (serverHelloMessage.getSelectedCipherSuite() != null && serverHelloMessage.getSelectedCipherSuite().getValue() != null) {
            res.append(HexConverter.bytesToHex(serverHelloMessage.getSelectedCipherSuite().getValue())).append("_");
        } else {
            res.append("null").append("_");
        }

        if (serverHelloMessage.getExtensions() == null) {
            res.append("null").append("_");
        } else {
            for (ExtensionMessage e : serverHelloMessage.getExtensions()) {
                // if it's some special Extension (such as Heartbeat), append the content of it, else append the length
                if (e.getExtensionType() != null && e.getExtensionType().getValue() != null) {
                    res.append(HexConverter.bytesToHex(e.getExtensionType().getValue())).append("_");
                    switch (ExtensionType.getExtensionType(e.getExtensionType().getValue())) {
                        case HEARTBEAT:
                        case ELLIPTIC_CURVES:
                        case EC_POINT_FORMATS:
                        case SIGNATURE_AND_HASH_ALGORITHMS:
                            if (e.getExtensionLength().getValue() == 0) {
                                res.append(e.getExtensionLength().getValue()).append("_");
                            } else {
                                res.append(HexConverter.bytesToHex(e.getExtensionBytes().getValue())).append("_");
                            }
                            break;
                        case SESSION_TICKET:
                        case RENEGOTIATION_INFO:
                        default:
                            res.append(e.getExtensionLength().getValue()).append("_");
                    }
                } else {
                    res.append("null").append("_");
                }
            }
        }

        return res.substring(0, res.length() - 1);
    }

    protected String parseServerKeyExchange(ServerKeyExchangeMessage serverKeyExchangeMessage) {
        StringBuilder res = new StringBuilder(serverKeyExchangeMessage.toCompactString()).append("_");

        if (serverKeyExchangeMessage.getLength() != null && serverKeyExchangeMessage.getLength().getValue() != null) {
            res.append(serverKeyExchangeMessage.getLength().getValue());
        } else {
            res.append("null");
        }

        return res.toString();
    }

    protected String parseCertificateRequest(CertificateRequestMessage certificateRequestMessage) {
        StringBuilder res = new StringBuilder("CERTIFICATE_REQUEST_");

        if (certificateRequestMessage.getClientCertificateTypes() != null &&
                certificateRequestMessage.getClientCertificateTypes().getValue() != null) {
            // add Certificate Types Count
            res.append(certificateRequestMessage.getClientCertificateTypesCount().getValue()).append("_");
            // add Certificate Types
            res.append(HexConverter.bytesToHex(certificateRequestMessage.getClientCertificateTypes().getValue()).replaceAll("(.{2})", "$1_"));
        } else {
            res.append("null").append("_");
        }

        if (certificateRequestMessage.getSignatureHashAlgorithms() != null && certificateRequestMessage.getSignatureHashAlgorithms().getValue() != null) {
            res.append(certificateRequestMessage.getSignatureHashAlgorithmsLength().getValue()).append("_");
            try {
                List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms =
                        SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(certificateRequestMessage.getSignatureHashAlgorithms().getValue());
                for (SignatureAndHashAlgorithm algo : signatureAndHashAlgorithms) {
                    res.append(HexConverter.bytesToHex(algo.getByteValue())).append("_");
                }
            } catch (Exception var5) {
                System.out.println("Error: Parse SignatureAndHashAlgorithms in CertificateRequest.");
            }
        } else {
            res.append("null").append("_");
        }

        return res.substring(0, res.length() - 1);
    }

    protected String parseNewSessionTicket(NewSessionTicketMessage sessionTicketMessage) {
        StringBuilder res = new StringBuilder("NEW_SESSION_TICKET_");
        if (sessionTicketMessage.getTicketLifetimeHint() != null && sessionTicketMessage.getTicketLifetimeHint().getValue() != null) {
            res.append(sessionTicketMessage.getTicketLifetimeHint().getValue()).append("_");
        } else {
            res.append("null").append("_");
        }

        if (sessionTicketMessage.getTicketLength() != null && sessionTicketMessage.getTicketLength().getValue() != null) {
            res.append(sessionTicketMessage.getTicketLength().getValue());
        } else {
            res.append("null");
        }

        return res.toString();
    }

    protected String parseHeartbeatProtocol(HeartbeatMessage heartbeatMessage) {
        StringBuilder res = new StringBuilder("HEARTBEAT_");

        if (heartbeatMessage.getHeartbeatMessageType() != null && heartbeatMessage.getHeartbeatMessageType().getValue() != null) {
            res.append(HeartbeatMessageType.getHeartbeatMessageType(heartbeatMessage.getHeartbeatMessageType().getValue())).append("_");
        } else {
            res.append("null").append("_");
        }

        if (heartbeatMessage.getPayload() != null && heartbeatMessage.getPayload().getValue() != null) {
            res.append(HexConverter.bytesToHex(heartbeatMessage.getPayload().getValue()));
        } else {
            res.append("null");
        }

        return res.toString();
    }
}

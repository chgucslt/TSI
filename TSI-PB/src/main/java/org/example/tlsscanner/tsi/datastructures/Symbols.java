package org.example.tlsscanner.tsi.datastructures;

public interface Symbols {

    String CH = "ClientHelloExtendedRenegotiation";
    String CERT = "CertificateEmpty";
    String CKE = "ClientKeyExchange";
    String CCS = "ChangeCipherSpec";
    String FIN = "Finished";
    String ALERT = "AlertWarningCloseNotify";
    String APP = "ApplicationData";

    String CONNECTION_CLOSED = "x";
    String NO_RESPONSE = "-";
}

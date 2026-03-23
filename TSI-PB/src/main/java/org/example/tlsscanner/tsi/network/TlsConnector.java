package org.example.tlsscanner.tsi.network;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.*;

import static org.example.tlsscanner.tsi.datastructures.Symbols.CONNECTION_CLOSED;
import static org.example.tlsscanner.tsi.datastructures.Symbols.NO_RESPONSE;

public class TlsConnector {

    String targetIp;
    int port;
    int timeout; // in milliseconds

    HashMap<String, WorkflowTrace> messages = new HashMap<>();
    List<String> cipherSuiteStrings;
    String tlsVersion;
    String compressionMethodString;

    private de.rub.nds.tlsattacker.core.config.Config config;
    private de.rub.nds.tlsattacker.core.state.State state;

    // 私有无參数构造函数，供其他构造函数调用以避免重复代码
    private TlsConnector() {
        Security.addProvider(new BouncyCastleProvider());

        UnlimitedStrengthEnabler.enable();

        Configurator.setAllLevels("de.rub.nds.tlsattacker", org.apache.logging.log4j.Level.OFF);
    }

    public TlsConnector(
            String targetIp,
            int port,
            int timeout,
            String messageDir,
            String cipherSuites,
            String tlsVersion,
            String compressionMethod) {
        this();
        this.targetIp = targetIp;
        this.port = port;
        this.timeout = timeout;
        this.tlsVersion = tlsVersion;
        this.compressionMethodString = compressionMethod;
        this.cipherSuiteStrings = List.of(cipherSuites.split(" "));

        try {
            loadMessages(messageDir);
        } catch (IOException | XMLStreamException | JAXBException e) {
            throw new RuntimeException("Failed to load messages from " + messageDir + ": " + e.getMessage());
        }
        // Initialize TLS client
        initialise();
    }

    public void initialise() {
        config = de.rub.nds.tlsattacker.core.config.Config.createConfig();
        config.setEnforceSettings(false);

        OutboundConnection clientConnection = new OutboundConnection(port, targetIp);
        clientConnection.setTimeout(timeout);
        config.setDefaultClientConnection(clientConnection);


        List<CipherSuite> cipherSuites = new LinkedList<>();
        for (String cipherSuiteString: this.cipherSuiteStrings) {
            try {
                cipherSuites.add(CipherSuite.valueOf(cipherSuiteString));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid cipher suite: " + cipherSuiteString);
            }
        }
        if (cipherSuites.isEmpty()) {
            cipherSuites = Arrays.asList(CipherSuite.values());
        }
        // Set default selected CipherSuite. This will be the first in the list of specified CipherSuites
        config.setDefaultSelectedCipherSuite(cipherSuites.get(0));
        // Set the list of supported cipher suites
        config.setDefaultClientSupportedCipherSuites(cipherSuites);


        List<CompressionMethod> compressionMethods = new LinkedList<>();
        CompressionMethod compressionMethod;
        try {
            compressionMethod = CompressionMethod.valueOf(compressionMethodString);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid compression method: " + compressionMethodString);
        }
        compressionMethods.add(compressionMethod);
        // Set supported compression algorithms
        config.setDefaultClientSupportedCompressionMethods(compressionMethods);


        ProtocolVersion protocolVersion = ProtocolVersion.fromString(tlsVersion);
        config.setHighestProtocolVersion(protocolVersion);
        config.setDefaultSelectedProtocolVersion(protocolVersion);
        config.setDefaultHighestClientProtocolVersion(protocolVersion);


        config.setDefaultClientDhGenerator(new BigInteger("2"));
        config.setDefaultClientDhModulus(new BigInteger("6668014432879854274002278852208614463049243575172486268847999412414761893973482255240669516874141524239224030057949495697186951824868185545819975637245503840103415249493026666167468715286478870340074507098367006866803177055300900777576918011"));
        config.setDefaultClientDhPrivateKey(new BigInteger("30757838539894352412510553993926388250692636687493810307136098911018166940950"));
        config.setDefaultClientDhPublicKey(new BigInteger("6668014432879854274002278852208614463049243575172486268847999412414761893973482255240669516874141524239224030057949495697186951824868185545819975637245503840103415249493026666167468715286478870340074507098367006866803177055300900777576918011"));
        config.setDefaultServerDhPrivateKey(new BigInteger("30757838539894352412510553993926388250692636687493810307136098911018166940950"));
        config.setDefaultServerDhPublicKey(new BigInteger("6668014432879854274002278852208614463049243575172486268847999412414761893973482255240669516874141524239224030057949495697186951824868185545819975637245503840103415249493026666167468715286478870340074507098367006866803177055300900777576918011"));

        initialiseSession();
    }

    protected void initialiseSession() {
        state = new de.rub.nds.tlsattacker.core.state.State(config);
        TlsContext context = state.getTlsContext();
        ConnectorTransportHandler transportHandler = new ConnectorTransportHandler(
                config.getDefaultClientConnection().getTimeout(),
                config.getDefaultClientConnection().getHostname(),
                config.getDefaultClientConnection().getPort()
        );
        context.setTransportHandler(transportHandler);

        context.initTransportHandler();
        context.initRecordLayer();
    }

    public void close() {
        try {
            state.getTlsContext().getTransportHandler().closeClientConnection();
        } catch (IOException e) {
            throw new RuntimeException("Failed to close TLS session: " + e.getMessage());
        }
    }

    public void reset() {
        close();
        initialiseSession();
    }

    public String processInput(String inputSymbol, Symbolizer symbolizer) {
        try {
            // Check if the socket is already closed, in which case we don't have to bother trying to send data out
            if (state.getTlsContext().getTransportHandler().isClosed()) {
                return CONNECTION_CLOSED;
            }

            // Process the regular input symbol by sending the corresponding message and returning the response
            if (messages.containsKey(inputSymbol)) {
                sendMessage(messages.get(inputSymbol));
            } else {
                throw new RuntimeException("Unknown input symbol: " + inputSymbol);
            }

            return receiveMessage(symbolizer);
        } catch (IOException e) {
            throw new RuntimeException("Failed to process input symbol (" + inputSymbol + "): " + e.getMessage());
        }
    }

    private void sendMessage(WorkflowTrace trace) {
        for (TlsAction tlsAction: trace.getTlsActions()) {
            try {
                tlsAction.normalize();
                tlsAction.execute(state);
            } catch (WorkflowExecutionException e) {
                throw new RuntimeException("Failed to send message: " + e.getMessage());
            }
        }
        // Reset trace so we can execute it again
        trace.reset();
    }

    private String receiveMessage(Symbolizer symbolizer) throws IOException {
        if (state.getTlsContext().getTransportHandler().isClosed()) {
            return CONNECTION_CLOSED;
        }

        List<String> receivedMessages = new LinkedList<>();
        ReceiveAction action = new ReceiveAction(new LinkedList<ProtocolMessage>());
        // Need to normalize otherwise an exception is thrown about no connection existing with alias 'null'
        action.normalize();
        // Perform the actual receiving of the message
        action.execute(state);

        // Check for every record if the MAC is valid. If it is not, do not
        // continue reading it since its contents might be illegible.
        for (AbstractRecord abstractRecord : action.getReceivedRecords()) {
            if (BlobRecord.class.isAssignableFrom(abstractRecord.getClass())) {
                receivedMessages.add("blobRecord");
                continue;
            }

            Record record = (Record) abstractRecord;
            if (record.getComputations() == null) {
                continue;
            }
            if (record.getComputations().getMacValid() == null) {
                continue;
            }
            if (!record.getComputations().getMacValid()) {
                if (state.getTlsContext().getTransportHandler().isClosed()) {
                    return "InvalidMAC|" + CONNECTION_CLOSED;
                } else {
                    return "InvalidMAC";
                }
            }
        }

        String outputMessage;
        // Iterate over all received messages and build a string containing their respective types
        for (ProtocolMessage message : action.getReceivedMessages()) {
            outputMessage = symbolizer.symbolize((TlsMessage) message);
            if (!Objects.equals(outputMessage, "")) {
                receivedMessages.add(outputMessage);
            }
        }

        if (state.getTlsContext().getTransportHandler().isClosed()) {
            receivedMessages.add(CONNECTION_CLOSED);
        }

        if (!receivedMessages.isEmpty()) {
            return String.join("|", receivedMessages);
        } else {
            return NO_RESPONSE;
        }
    }

    private void loadMessages(String messageDir) throws IOException, XMLStreamException, JAXBException {
        File dir = new File(messageDir);

        if (!dir.isDirectory()) {
            System.err.println("Message directory is not valid: " + messageDir);
            throw new IllegalArgumentException("Message directory is not valid: " + messageDir);
        }

        // Get a list of all *.xml files in the provided directory
        File[] files = dir.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                return name.toLowerCase().endsWith(".xml");
            }
        });

        for (File file : files) {
            // Strip .xml from the end to get the message name
            String name = file.getName().substring(0, file.getName().length() - 4);

            // Read the workflow trace from the file
            FileInputStream input = new FileInputStream(file.getAbsolutePath());
            WorkflowTrace trace = WorkflowTraceSerializer.secureRead(input);

            messages.put(name, trace);
        }
    }

    public String getTargetIp() {
        return targetIp;
    }

    public int getPort() {
        return port;
    }


    public static void main(String[] args) {
        TlsConnector connector = new TlsConnector(
                "www.baidu.com",
                443,
                800,
                "src/main/resources/messages",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS12",
                "NULL"
        );
        Symbolizer symbolizer = new DefaultSymbolizer();

        String inputString = "ClientHelloExtendedRenegotiation, ClientKeyExchangeECDH, ChangeCipherSpec, Finished";

        for (String inputSymbol: inputString.split(", ")) {
            System.out.println("Input Symbol:" + inputSymbol);
            String outputSymbol = connector.processInput(inputSymbol, symbolizer);
            System.out.println("Output Symbol:" + outputSymbol);
        }
    }
}

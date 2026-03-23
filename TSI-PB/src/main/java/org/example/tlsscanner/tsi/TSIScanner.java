package org.example.tlsscanner.tsi;

import lombok.extern.slf4j.Slf4j;
import org.example.tlsscanner.api.GenericScanner;
import org.example.tlsscanner.common.JsonExporter;
import org.example.tlsscanner.config.ConfigurationManager;
import org.example.tlsscanner.tsi.analyzer.HomogeneityCalculator;
import org.example.tlsscanner.tsi.datastructures.TSIFingerprint;
import org.example.tlsscanner.tsi.datastructures.TSIInput;
import org.example.tlsscanner.tsi.datastructures.TSIOutput;
import org.example.tlsscanner.tsi.datastructures.Symbols;
import org.example.tlsscanner.tsi.analyzer.TSIFingerprintComparator;
import org.example.tlsscanner.tsi.analyzer.VersionIdentifier;
import org.example.tlsscanner.tsi.analyzer.VulnerabilityIdentifier;
import org.example.tlsscanner.tsi.dto.HomogeneityReport;
import org.example.tlsscanner.tsi.dto.ScanReport;
import org.example.tlsscanner.tsi.network.DefaultSymbolizer;
import org.example.tlsscanner.tsi.network.PreflightSymbolizer;
import org.example.tlsscanner.tsi.network.Symbolizer;
import org.example.tlsscanner.tsi.network.TlsConnector;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j
public class TSIScanner extends GenericScanner<TSIFingerprint, TSIInput, TSIOutput> {

    private ConfigurationManager config;
    private List<TSIInput> probes;
    private List<TSIFingerprint> candidateFingerprints;
    private JsonExporter jsonExporter;
    private HomogeneityCalculator homogeneityCalculator;

    // 每扫描一个目标，就需要重置以下变量
    private String targetIp;
    private int targetPort;
    private TlsConnector tlsConnector;
    private Map<String, List<String>> cachedInputsAndOutputs;
    private String preferredCipherSuite;
    private boolean rejectEmptyCertificate;
    private TSIFingerprint extractedFingerprint;
    private Map<TSIFingerprint, Double> identifiedVersions;
    private Map<String, List<String>> identifiedVulnerabilities;


    public TSIScanner(String scanId, ConfigurationManager config, List<String> targets) {
        super(scanId, targets);

        this.config = config;
        this.jsonExporter = new JsonExporter();
        this.homogeneityCalculator = new HomogeneityCalculator(new TSIFingerprintComparator());
        try {
            this.probes = TSIInput.fromFile(config.getProbesPath());
            this.candidateFingerprints = TSIFingerprint.fromFiles(config.getFingerprintsPath());
        } catch (IOException e) {
            log.error("{}", e.getMessage(), e);
            throw new RuntimeException("Failed to initialize HomogeneityScanner: " + e.getMessage(), e);
        }
    }

    @Override
    public void reset() {
        // 重置扫描状态
        super.reset();
        // 重置同质性
        this.homogeneityCalculator.reset();
        // 重置指纹
        this.resetStates();
    }

    private void saveStates() {
        // Build output file path using cross-platform Path API
        Path outputDir = Paths.get(config.getOutputDir());

        // Ensure output directory exists, create if necessary
        try {
            Files.createDirectories(outputDir);
        } catch (IOException e) {
            log.error("Failed to create output directory: {}", outputDir, e);
            return;
        }

        // Construct filename with proper format
        String filename = String.format("%s_fingerprint_%s_%d.json",
                getScanId(), targetIp, targetPort);

        Path outputPath = outputDir.resolve(filename);
        String outputFilePath = outputPath.toString();

        ScanReport scanReport = new ScanReport(
                targetIp,
                targetPort,
                preferredCipherSuite,
                rejectEmptyCertificate,
                extractedFingerprint,
                identifiedVersions,
                identifiedVulnerabilities
        );
        jsonExporter.export(scanReport, outputFilePath);
    }

    private void resetStates() {
        this.targetIp = null;
        this.targetPort = -1;
        this.tlsConnector = null;
        this.cachedInputsAndOutputs = new HashMap<>();
        this.preferredCipherSuite = null;
        this.rejectEmptyCertificate = false;
        this.extractedFingerprint = null;
        this.identifiedVersions = null;
        this.identifiedVulnerabilities = null;
    }

    @Override
    protected void generateReport() {
        // 保留 LinkedHashMap 的顺序特性，将其转换为 List 以便后续处理
        List<TSIFingerprint> fingerprints = getTargetFingerprints().values().stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        // 计算同质性
        homogeneityCalculator.calculate(fingerprints);

        // Build output file path using cross-platform Path API
        Path outputDir = Paths.get(config.getOutputDir());

        // Ensure output directory exists, create if necessary
        try {
            Files.createDirectories(outputDir);
        } catch (IOException e) {
            log.error("Failed to create output directory: {}", outputDir, e);
            return;
        }

        // Construct filename with proper format
        String filename = String.format("%s_homogeneity.json", getScanId());

        Path outputPath = outputDir.resolve(filename);
        String outputFilePath = outputPath.toString();
        HomogeneityReport report = new HomogeneityReport(
                getTargets(),
                homogeneityCalculator.getHomogeneity(),
                homogeneityCalculator.getFingerprintSimilarities()
        );
        jsonExporter.export(report, outputFilePath);
    }

    @Override
    public TSIFingerprint scanTarget(String target) {
        // 重置状态变量
        resetStates();

        // 解析目标地址，提取 IP 和端口
        targetIp = target.split(":")[0];
        targetPort = Integer.parseInt(target.split(":")[1]);

        extractedFingerprint = new TSIFingerprint(target);
        tlsConnector = new TlsConnector(
                targetIp,
                targetPort,
                config.getSocketTimeout(),
                config.getMessagesPath(),
                config.getTlsCipherSuites(),
                config.getTlsVersion(),
                config.getTlsCompressionMethod()
        );

        // 先进行 Preflight 阶段的检查，确保目标服务器可达，并记录基本的元数据特征（如使用的协议版本、CipherSuite 类型等）
        if (!preflight(target)) {
            log.error("Preflight checks failed for target: {}", target);
            return null;
        }

        // 逐个发送探针，记录响应特征，并利用缓存优化扫描过程
        for (TSIInput input : probes) {
            // 查询缓存
            TSIOutput output = queryCache(input);

            if (output != null) {
                log.debug("Cache hit for probe: {}", input.getRawString());
            } else {
                // 如果缓存中没有匹配的记录，则发送探针并记录响应特征
                output = processProbe(input);
                // 更新缓存
                if (updateCache(input, output)) {
                    log.debug("Cache updated for probe: {}", input.getRawString());
                }
            }

            extractedFingerprint.put(input, output);

            try {
                TimeUnit.MILLISECONDS.sleep(config.getSocketInterval());
            } catch (InterruptedException e) {
                log.warn("Sleep interrupted: {}", e.getMessage());
//                Thread.currentThread().interrupt();
            }
        }

        // 与已知指纹进行对比，计算相似度得分
        VersionIdentifier versionIdentifier = new VersionIdentifier(new TSIFingerprintComparator());
        identifiedVersions = versionIdentifier.startIdentification(
                extractedFingerprint, candidateFingerprints, config.getSimilarityThreshold());

        // 根据已识别的版本信息，查询对应的漏洞信息
        VulnerabilityIdentifier vulnerabilityIdentifier = new VulnerabilityIdentifier();
        identifiedVulnerabilities = vulnerabilityIdentifier.startIdentification(
                config.getCveDatabasePath(),
                identifiedVersions.keySet().stream().map(TSIFingerprint::getSubject).collect(Collectors.toList()));

        // 保存扫描结果
        saveStates();

        return extractedFingerprint;
    }

    private TSIOutput processProbe(TSIInput input) {
        log.debug("-".repeat(40));

        tlsConnector.reset();

        List<String> outputSymbols = new ArrayList<>();

        Symbolizer symbolizer = new DefaultSymbolizer();
        for (String inputSymbol : input.getInputSymbols()) {
            // 如果服务器拒绝空证书，则跳过发送 CERT 探针
            if (rejectEmptyCertificate && inputSymbol.equals(Symbols.CERT)) {
                // 默认使用 NO_RESPONSE 作为空证书的响应
                // 目的是与指纹数据库中的格式保持一致，方便对比
                outputSymbols.add(Symbols.NO_RESPONSE);
                continue;
            }

            // 处理 ClientKeyExchange 和 ClientKeyExchange~ 探针，
            // 根据服务器在 Preflight 阶段选择的 CipherSuite 类型，动态调整发送的探针类型
            if (inputSymbol.equals(Symbols.CKE + "~")) {
                inputSymbol = preferredCipherSuite.equals("ECDH") ? Symbols.CKE + "RSA" : Symbols.CKE + "ECDH";
            } else if (inputSymbol.equals(Symbols.CKE)) {
                inputSymbol = Symbols.CKE + preferredCipherSuite;
            }

            log.debug("Sending symbol: {}", inputSymbol);
            String outputSymbol = tlsConnector.processInput(inputSymbol, symbolizer);
            log.debug("Received symbol: {}", outputSymbol);
            outputSymbols.add(outputSymbol);

            // 如果连接已关闭，后续的探针都无需再发送（因为无论发送什么，返回都是 CONNECTION_CLOSED）
            if (outputSymbol.endsWith(Symbols.CONNECTION_CLOSED)) break;
        }

        log.debug("-".repeat(40));
        return TSIOutput.fromOutputSymbols(outputSymbols);
    }

    private boolean updateCache(TSIInput input, TSIOutput output) {
        List<String> inputSymbols = List.of(input.getInputSymbols());
        List<String> outputSymbols = output.getOutputSymbols();

        // 只记录有实际响应的探针（即至少有一个输出符号）
        if (outputSymbols.isEmpty()) return false;
        // 只记录导致连接关闭的探针
        if (!outputSymbols.get(outputSymbols.size() - 1).contains(Symbols.CONNECTION_CLOSED)) return false;
        // 如果输入符号数量多于输出符号数量，说明连接在某个探针消息后就被关闭了，此时只记录导致连接关闭的前部分探针消息及其响应
        if (inputSymbols.size() > outputSymbols.size()) {
            inputSymbols = inputSymbols.subList(0, outputSymbols.size());
        }

        cachedInputsAndOutputs.put(
                String.join(", ", inputSymbols),
                outputSymbols
        );

        return true;
    }

    private TSIOutput queryCache(TSIInput input) {
        List<String> inputSymbols = List.of(input.getInputSymbols());
        String queriedKey = String.join(", ", inputSymbols);
        for (String key : cachedInputsAndOutputs.keySet()) {
            if (queriedKey.startsWith(key)) {
                return TSIOutput.fromOutputSymbols(cachedInputsAndOutputs.get(key));
            }
        }
        // 如果没有找到任何匹配的缓存记录，则返回 null
        return null;
    }

    private boolean preflight(String target) {

        tlsConnector.reset();

        // 使用 PreflightSymbolizer 来分析服务器对 ClientHello 消息的响应，预期输出如下：
        // Version:TLS12$CipherSuite:C02F$Renegotiation:FF01_1$Heartbeat:False$ECPointFormats:000B_000B00020100|CERTIFICATE|ECDHEServerKeyExchange:329|SERVER_HELLO_DONE
        Symbolizer symbolizer = new PreflightSymbolizer();
        String response = tlsConnector.processInput(Symbols.CH, symbolizer);

        if (!response.contains("CipherSuite:")) {
            log.warn("Some error occurred during ClientHello preflight. Received response: {}", response);
            return false;
        }

        if (response.endsWith(Symbols.CONNECTION_CLOSED)) {
            log.warn("Can NOT connect to the target: {}. Received response: {}", target, response);
            return false;
        }

        String[] receivedMessages = response.split("\\|");
        List<String> output = new ArrayList<>();
        String[] serverHelloInfo = receivedMessages[0].split("\\$");
        // 记录 ServerHello 消息的特征（如协议版本、CipherSuite、CompressionMethod 等）
        output.addAll(List.of(serverHelloInfo));
        // 记录 ServerKeyExchange 和 CertificateRequest 消息的特征
        for (String msg : receivedMessages) {
            if (msg.contains("ECDHEServerKeyExchange:") || msg.contains("CertificateRequest:")) {
                output.add(msg);
            }
        }
        extractedFingerprint.put(
                TSIInput.fromLine(Symbols.CH),
                TSIOutput.fromOutputSymbols(output));

        // 记录服务器选择的 CipherSuite 类型，作为后续探针的参考
        String cipherSuiteCode = serverHelloInfo[1].split(":")[1];
        switch (cipherSuiteCode.toUpperCase()) {
            case "C02F":
                preferredCipherSuite = "ECDH";
                break;
            case "002F":
            case "000A":
                preferredCipherSuite = "RSA";
                break;
            case "0039":
            case "0033":
            case "0016":
                preferredCipherSuite = "DH";
                break;
            case "NULL":
                log.warn("Server selected NULL cipher suite, which is unusual. Received response: {}", response);
                return false;
            default:
                log.warn("Unknown CipherSuite code received: {}. Received response: {}", cipherSuiteCode, response);
                return false;
        }

        // 观察服务器是否拒绝空证书（如果是，则后续探针都不再发送空证书）
        response = tlsConnector.processInput(Symbols.CERT, symbolizer);
        rejectEmptyCertificate = response.endsWith(Symbols.CONNECTION_CLOSED);

        return true;
    }


}

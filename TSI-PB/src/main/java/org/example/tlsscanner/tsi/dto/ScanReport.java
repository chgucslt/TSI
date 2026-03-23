package org.example.tlsscanner.tsi.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import org.example.tlsscanner.tsi.datastructures.TSIFingerprint;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

@Getter
@Setter
public class ScanReport {

    @JsonProperty("timestamp")
    private String timestamp;

    @JsonProperty("target_ip")
    private String targetIp;

    @JsonProperty("target_port")
    private int targetPort;

    @JsonProperty("negotiation_algorithm")
    private String negotiationAlgorithm;

    @JsonProperty("reject_empty_certificate")
    private boolean rejectEmptyCertificate;

    @JsonProperty("fingerprint")
    private Map<String, List<String>> fingerprint;

    @JsonProperty("identified_version")
    private Map<String, Double> identifiedVersion;

    @JsonProperty("identified_vulnerabilities")
    private Map<String, List<String>>  identifiedVulnerabilities;

    public ScanReport() {}

    public ScanReport(
            String targetIp,
            int targetPort,
            String negotiationAlgorithm,
            boolean rejectEmptyCertificate,
            Map<String, List<String>> fingerprint,
            Map<String, Double> identifiedVersion,
            Map<String, List<String>>  identifiedVulnerabilities) {
        this.timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        this.targetIp = targetIp;
        this.targetPort = targetPort;
        this.negotiationAlgorithm = negotiationAlgorithm;
        this.rejectEmptyCertificate = rejectEmptyCertificate;
        this.fingerprint = fingerprint;
        this.identifiedVersion = identifiedVersion;
        this.identifiedVulnerabilities = identifiedVulnerabilities;
    }

    public ScanReport(
            String targetIp,
            int targetPort,
            String negotiationAlgorithm,
            boolean rejectEmptyCertificate,
            TSIFingerprint fingerprint,
            Map<TSIFingerprint, Double> identifiedVersion,
            Map<String, List<String>>  identifiedVulnerabilities) {
        // 按照 input 长度升序排列 fingerprint 中的条目，并转换为 LinkedHashMap<String, List<String>>
        LinkedHashMap<String, List<String>> sortedFingerprint = fingerprint.getFingerprint().entrySet().stream()
                .sorted(Comparator.comparingInt(e -> e.getKey().size()))
                .collect(Collectors.toMap(
                        entry -> entry.getKey().getRawString(),
                        entry -> entry.getValue().getOutputSymbols(),
                        (a, b) -> a,
                        LinkedHashMap::new
                ));
        // 根据得分降序排列 identifiedVersion 中的条目，并转换为 LinkedHashMap<String, Double>
        Map<String, Double> sortedIdentifiedVersion = identifiedVersion.entrySet().stream()
                .sorted(Map.Entry.<TSIFingerprint, Double>comparingByValue().reversed())
                .collect(Collectors.toMap(
                        entry -> entry.getKey().getSubject(),
                        Map.Entry::getValue,
                        (a, b) -> a,
                        LinkedHashMap::new
                ));
        // 按照影响范围（即漏洞列表长度）降序排列 identifiedVulnerabilities 中的条目，并转换为 LinkedHashMap<String, List<String>>
        LinkedHashMap<String, List<String>> sortedIdentifiedVulnerabilities = identifiedVulnerabilities.entrySet().stream()
                .sorted((e1, e2) -> Integer.compare(e2.getValue().size(), e1.getValue().size()))
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (a, b) -> a,
                        LinkedHashMap::new
                ));

        this.timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        this.targetIp = targetIp;
        this.targetPort = targetPort;
        this.negotiationAlgorithm = negotiationAlgorithm;
        this.rejectEmptyCertificate = rejectEmptyCertificate;
        this.fingerprint = sortedFingerprint;
        this.identifiedVersion = sortedIdentifiedVersion;
        this.identifiedVulnerabilities = sortedIdentifiedVulnerabilities;
    }

}

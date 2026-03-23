package org.example.tlsscanner.api;

import lombok.Getter;
import lombok.Setter;
import org.example.tlsscanner.api.datastructures.Fingerprint;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public abstract class GenericScanner<T extends Fingerprint<K, V>, K, V> implements Scanner {

    @Getter
    @Setter
    private List<String> targets;

    @Getter
    @Setter
    private String scanId;

    private Map<String, T> targetFingerprints;

    private boolean scanCompleted;

    public GenericScanner(String scanId, List<String> targets) {
        this.scanId = scanId;
        this.targets = targets;
        // 使用 LinkedHashMap 来保持插入顺序，确保后续输出时的顺序一致性
        this.targetFingerprints = new LinkedHashMap<>();
        this.scanCompleted = false;
    }

    public void reset() {
        // 重置状态变量，以允许重新扫描
        this.targetFingerprints = new LinkedHashMap<>();
        this.scanCompleted = false;
    }

    @Override
    public void start() {
        if (scanCompleted)
            throw new IllegalStateException("Scan already completed. Please reset before starting a new scan.");

        for (String target : targets) {
            T fingerprint = scanTarget(target);
            targetFingerprints.put(target, fingerprint);
        }
        scanCompleted = true;

        generateReport();
    }

    // 扫描单个目标并返回其 TLS 指纹信息，具体实现由子类完成
    public abstract T scanTarget(String target);

    // 生成报告的方法，具体实现由子类完成，可以根据需要输出不同格式的报告
    protected abstract void generateReport();


    public Map<String, T> getTargetFingerprints() {
        if (!scanCompleted) {
            throw new IllegalStateException("Scan not completed yet. Please call start() before accessing results.");
        }
        return targetFingerprints;
    }

}

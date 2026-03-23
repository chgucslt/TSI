package org.example.tlsscanner.api.datastructures;

import java.util.LinkedHashMap;
import java.util.Map;


/**
 * Fingerprint 类用于存储针对特定目标（subject）的探针输入和对应的响应特征列表。
 * 注意：范型参数 K 和 V 都必须正确实现 equals() 和 hashCode() 方法。
 *
 * @param <K> 输入类型，通常为 String，表示客户端发送的探针字符串
 * @param <V> 输出类型，通常为 List<String>，表示服务端响应的特征列表。
 */
public abstract class Fingerprint<K, V> {

    private final String subject;

    // Key 是输入的探针字符串（类型通常为 String）
    // Value 是对应的响应特征列表（类型通常为 List<String>）
    private Map<K, V> fingerprint;

    public Fingerprint(String subject) {
        this.subject = subject;
        // 使用 LinkedHashMap 保持插入顺序，方便后续输出时的顺序一致性
        this.fingerprint = new LinkedHashMap<>();
    }

    public void put(K input, V output) {
        fingerprint.put(input, output);
    }

    public String getSubject() {
        return subject;
    }

    public Map<K, V> getFingerprint() {
        return fingerprint;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Fingerprint for ").append(subject).append(":\n");
        for (Map.Entry<K, V> entry : fingerprint.entrySet()) {
            sb.append("  Input: ").append(entry.getKey()).append("\n");
            sb.append(" Output: ").append(entry.getValue()).append("\n");
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;

        Fingerprint<?, ?> that = (Fingerprint<?, ?>) obj;

        // 只有当 subject 和 fingerprint 都相等时才认为两个 Fingerprint 对象相等
        if (!subject.equals(that.subject)) return false;
        return fingerprint.equals(that.fingerprint);
    }

    @Override
    public int hashCode() {
        int result = subject.hashCode();
        result = 31 * result + fingerprint.hashCode();
        return result;
    }
}

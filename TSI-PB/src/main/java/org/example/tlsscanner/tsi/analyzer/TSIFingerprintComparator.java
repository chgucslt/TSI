package org.example.tlsscanner.tsi.analyzer;

import lombok.extern.slf4j.Slf4j;
import org.example.tlsscanner.api.FingerprintComparator;
import org.example.tlsscanner.tsi.datastructures.TSIFingerprint;
import org.example.tlsscanner.tsi.datastructures.TSIInput;
import org.example.tlsscanner.tsi.datastructures.TSIOutput;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Slf4j
public class TSIFingerprintComparator implements FingerprintComparator<TSIFingerprint, TSIInput, TSIOutput> {

    @Override
    public double calculate(TSIFingerprint f1, TSIFingerprint f2) {
        // 记录两个指纹之间的最大可能得分
        double maxScore = 0.0;
        // 记录两个指纹之间的实际得分
        double score = 0.0;

        Map<TSIInput, TSIOutput> fingerprint1 = f1.getFingerprint();
        Map<TSIInput, TSIOutput> fingerprint2 = f2.getFingerprint();

        for (TSIInput input : fingerprint1.keySet()) {
            if (fingerprint2.containsKey(input)) {
                TSIOutput output1 = fingerprint1.get(input);
                TSIOutput output2 = fingerprint2.get(input);
                // 理论最大得分是两个输出列表长度的最小值，因为我们只能比较相同数量的特征
                int minSize = Math.min(output1.size(), output2.size());
                maxScore += minSize;
                // 实际得分是两个输出列表的交集大小
                Set<String> set1 = new HashSet<>(output1.getOutputSymbols());
                Set<String> set2 = new HashSet<>(output2.getOutputSymbols());
                set1.retainAll(set2);
                score += set1.size();
            }
        }

        log.debug("Comparing {} and {}: score = {}, maxScore = {}", f1.getSubject(), f2.getSubject(), score, maxScore);
        return maxScore == 0.0 ? 0.0 : (score / maxScore);
    }
}

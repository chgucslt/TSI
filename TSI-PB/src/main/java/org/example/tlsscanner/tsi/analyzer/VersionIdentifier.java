package org.example.tlsscanner.tsi.analyzer;

import lombok.Getter;
import lombok.Setter;
import org.example.tlsscanner.api.FingerprintComparator;
import org.example.tlsscanner.tsi.datastructures.TSIFingerprint;
import org.example.tlsscanner.tsi.datastructures.TSIInput;
import org.example.tlsscanner.tsi.datastructures.TSIOutput;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


public class VersionIdentifier {

    @Setter
    @Getter
    private FingerprintComparator<TSIFingerprint, TSIInput, TSIOutput> comparator;

    public VersionIdentifier(TSIFingerprintComparator comparator) {
        this.comparator = comparator;
    }

    public Map<TSIFingerprint, Double> startIdentification(
            TSIFingerprint targetFingerprint,
            List<TSIFingerprint> knownFingerprints,
            double similarityThreshold) {

        return knownFingerprints.stream()
                .map(candidate -> Map.entry(candidate, comparator.calculate(targetFingerprint, candidate)))
                .filter(entry -> entry.getValue() >= similarityThreshold)
                .sorted(Map.Entry.<TSIFingerprint, Double>comparingByValue().reversed())
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (a, b) -> a,
                        LinkedHashMap::new
                ));
    }
}

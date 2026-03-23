package org.example.tlsscanner.tsi.analyzer;

import lombok.Getter;
import lombok.Setter;
import org.example.tlsscanner.api.FingerprintComparator;
import org.example.tlsscanner.tsi.datastructures.TSIFingerprint;
import org.example.tlsscanner.tsi.datastructures.TSIInput;
import org.example.tlsscanner.tsi.datastructures.TSIOutput;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HomogeneityCalculator {

    @Setter
    @Getter
    private FingerprintComparator<TSIFingerprint, TSIInput, TSIOutput> comparator;

    private List<TSIFingerprint> fingerprints;
    private double homogeneity;
    private Map<String, Double> fingerprintSimilarities;
    private boolean calculated;

    public HomogeneityCalculator(TSIFingerprintComparator comparator) {
        this.comparator = comparator;
        reset();
    }

    public void reset() {
        this.fingerprints = null;
        this.homogeneity = 0.0;
        this.fingerprintSimilarities = new HashMap<>();
        this.calculated = false;
    }

    public void calculate(List<TSIFingerprint> fingerprints) {
        if (calculated)
            throw new IllegalStateException("Homogeneity has already been calculated. Please call reset() before calculating again.");

        this.fingerprints = fingerprints;

        if (fingerprints == null || fingerprints.size() < 2) {
            this.homogeneity = 1.0;  // Homogeneity is perfect if there's only one or no fingerprints
            this.calculated = true;
            return;
        }

        double totalSimilarity = 0.0;
        int pairCount = 0;

        for (int i = 0; i < fingerprints.size(); i++) {
            for (int j = i + 1; j < fingerprints.size(); j++) {
                // Join the fingerprint IDs in a consistent order to form the key
                String comparedFingerprints = fingerprints.get(i).getSubject().compareTo(fingerprints.get(j).getSubject()) < 0
                        ? fingerprints.get(i).getSubject() + "<->" + fingerprints.get(j).getSubject()
                        : fingerprints.get(j).getSubject() + "<->" + fingerprints.get(i).getSubject();
                // Delegate the similarity calculation to the strategy
                double similarity = comparator.calculate(fingerprints.get(i), fingerprints.get(j));

                this.fingerprintSimilarities.put(comparedFingerprints, similarity);
                totalSimilarity += similarity;
                pairCount++;
            }
        }

        this.homogeneity = totalSimilarity / pairCount; // Average similarity across all pairs
        this.calculated = true;
    }

    public List<TSIFingerprint> getFingerprints() {
        if (!calculated)
            throw new IllegalStateException("Homogeneity has not been calculated yet. Please call calculate() first.");
        return fingerprints;
    }

    public double getHomogeneity() {
        if (!calculated)
            throw new IllegalStateException("Homogeneity has not been calculated yet. Please call calculate() first.");
        return homogeneity;
    }

    public Map<String, Double> getFingerprintSimilarities() {
        if (!calculated)
            throw new IllegalStateException("Homogeneity has not been calculated yet. Please call calculate() first.");
        return fingerprintSimilarities;
    }
}

package org.example.tlsscanner.tsi.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Getter
@Setter
public class HomogeneityReport {

    @JsonProperty("timestamp")
    private String timestamp;

    @JsonProperty("targets")
    private List<String> targets;

    @JsonProperty("homogeneity")
    private double  homogeneity;

    @JsonProperty("target_similarities")
    private Map<String, Double> targetSimilarities;

    public HomogeneityReport() {}

    public HomogeneityReport(
            List<String> targets,
            double homogeneity,
            Map<String, Double> targetSimilarities) {
        this.timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        this.targets = targets;
        this.homogeneity = homogeneity;
        this.targetSimilarities = targetSimilarities;
    }
}

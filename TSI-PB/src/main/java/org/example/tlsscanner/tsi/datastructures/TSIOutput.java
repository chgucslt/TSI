package org.example.tlsscanner.tsi.datastructures;

import lombok.Getter;

import java.util.List;

@Getter
public class TSIOutput {

    private List<String> outputSymbols;

    private TSIOutput(List<String> outputSymbols) {
        this.outputSymbols = outputSymbols;
    }

    public static TSIOutput fromOutputSymbols(List<String> outputSymbols) {
        return new TSIOutput(outputSymbols);
    }

    public int size() {
        return outputSymbols.size();
    }

    @Override
    public String toString() {
        return String.join(", ", outputSymbols);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;

        TSIOutput other = (TSIOutput) obj;
        return this.outputSymbols.equals(other.outputSymbols);
    }

    @Override
    public int hashCode() {
        return outputSymbols.hashCode();
    }
}

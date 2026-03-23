package org.example.tlsscanner.tsi.datastructures;

import lombok.Getter;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

@Getter
public class TSIInput {

    private String rawString;
    private String[] inputSymbols;

    private TSIInput(String rawString, String[] inputSymbols) {
        this.rawString = rawString;
        this.inputSymbols = inputSymbols;
    }

    public static TSIInput fromLine(String line) {
        String rawString = line.trim();
        String[] inputSymbols = rawString.split(", ");

        // TODO：检查输入符号是否合法，例如是否为预定义的探针类型（ClientHello, ClientKeyExchange, ChangCipherSpec, Finished）

        return new TSIInput(rawString, inputSymbols);
    }

    public static List<TSIInput> fromFile(String filePath) throws IOException {
        Path path = Paths.get(filePath);

        if (!Files.exists(path)) {
            throw new FileNotFoundException("Probe file not found: " + filePath);
        }

        try {
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);

            return lines.stream()
                    .map(String::trim)
                    .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                    .map(TSIInput::fromLine)
                    .collect(Collectors.toList());

        } catch (IOException e) {
            throw new RuntimeException("Failed to read probe file: " + e.getMessage(), e);
        }
    }

    public int size() {
        return inputSymbols.length;
    }

    @Override
    public String toString() {
        return rawString;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;

        TSIInput probe = (TSIInput) obj;
        return rawString.equals(probe.rawString);
    }

    @Override
    public int hashCode() {
        return rawString.hashCode();
    }
}

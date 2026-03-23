package org.example.tlsscanner.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
public class JsonExporter {

    private final ObjectMapper objectMapper;

    public JsonExporter() {
        this.objectMapper = new ObjectMapper();
        // 自动格式化输出 JSON
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    public void export(Object data, String outputFilePath) {
        Path path = Paths.get(outputFilePath);
        try {
            // 确保父目录存在
            Files.createDirectories(path.getParent());
            // 将对象写入 JSON 文件
            objectMapper.writeValue(path.toFile(), data);
            log.info("Successfully exported data to JSON file: {}", outputFilePath);
        } catch (IOException e) {
            log.error("Failed to export data to JSON file: {}", outputFilePath, e);
        }

    }
}

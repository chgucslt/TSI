package org.example.tlsscanner.tsi.datastructures;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.tlsscanner.api.datastructures.Fingerprint;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


public class TSIFingerprint extends Fingerprint<TSIInput, TSIOutput> {

    public TSIFingerprint(String subject) {
        super(subject);
    }

    /**
     * 读取指定目录下的所有 JSON 文件，并将它们解析为 HomogeneityFingerprint 对象列表。
     *
     * @param dirPath 包含指纹 JSON 文件的目录路径
     * @return 一个包含所有解析成功的 HomogeneityFingerprint 对象的列表
     * @throws IOException 如果目录不存在、无法访问，或者文件内容无法正确解析为 JSON 时抛出异常
     */
    public static List<TSIFingerprint> fromFiles(String dirPath) throws IOException {
        File dir = new File(dirPath);
        if (!dir.exists() || !dir.isDirectory()) {
            throw new IllegalArgumentException("Directory not found: " + dirPath);
        }

        File[] files = dir.listFiles();
        if (files == null) {
            throw new IOException("Failed to list files in directory: " + dirPath);
        }

        List<TSIFingerprint> fingerprints = new ArrayList<>();
        for (File file: files) {
            if (file.isFile() && file.getName().toLowerCase().endsWith(".json")) {
                fingerprints.add(fromFile(file));
            }
        }
        return fingerprints;
    }

    /**
     * 从单个 JSON 文件中解析出一个 HomogeneityFingerprint 对象。
     * 文件内容应为一个 JSON 对象，其中键是输入字符串，值是对应的输出特征列表。
     *
     * @param file 包含指纹数据的 JSON 文件
     * @return 从文件中解析得到的 HomogeneityFingerprint 对象
     * @throws IOException 如果文件无法访问，或者内容无法正确解析为 JSON 时抛出异常
     */
    public static TSIFingerprint fromFile(File file) throws IOException {
        try {
            // 使用文件名（去掉扩展名）作为指纹的对象
            String fileName = file.getName().replaceFirst("[.][^.]+$", "");
            TSIFingerprint fingerprint = new TSIFingerprint(fileName);

            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, List<String>> data = objectMapper.readValue(file, new TypeReference<>() {});
            for (Map.Entry<String, List<String>> entry : data.entrySet()) {
                TSIInput input = TSIInput.fromLine(entry.getKey());
                TSIOutput output = TSIOutput.fromOutputSymbols(entry.getValue());
                fingerprint.put(input, output);
            }

            return fingerprint;
        } catch (IOException e) {
            throw new IOException("Failed to read fingerprint from file: " + file.getName(), e);
        }
    }
}

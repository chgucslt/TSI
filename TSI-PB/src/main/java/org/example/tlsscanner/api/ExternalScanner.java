package org.example.tlsscanner.api;

import lombok.extern.slf4j.Slf4j;
import org.example.tlsscanner.api.datastructures.Fingerprint;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
public abstract class ExternalScanner<T extends Fingerprint<K, V>, K, V> extends GenericScanner<T, K, V> {
    /***
     * 基于外部 TLS 扫描工具（例如，testssl.sh）构建 Target Server 的指纹
     */

    private final String externalToolName;
    private final String externalToolPath;
    // 设置命令执行的超时时间，单位为秒
    private long timeoutSeconds;

    public ExternalScanner(
            String scanId,
            List<String> targets,
            String toolName,
            String externalToolPath,
            long timeoutSeconds) {
        super(scanId, targets);
        this.externalToolName = toolName;
        this.externalToolPath = externalToolPath;
        this.timeoutSeconds = timeoutSeconds;
    }

    public ExternalScanner(
            String scanId,
            List<String> targets,
            String toolName,
            String externalToolPath) {
        this(scanId, targets, toolName, externalToolPath, 600); // 默认超时时间为600秒
    }

    boolean executeCommand(List<String> command) {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);

        try {
            Process process = pb.start();
            // 捕获并记录外部工具的输出
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
                log.info("[{}] {}", externalToolName, line);
            }
            // 等待进程完成，设置超时时间
            boolean completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!completed) {
                log.warn("{} command timed out after {} seconds: {}", externalToolName, timeoutSeconds, String.join(" ", command));
                process.destroyForcibly();
                return false;
            }
            // 获取退出码并记录日志
            int exitCode = process.exitValue();
            log.info("{} command completed with exit code: {}", externalToolName, exitCode);
            return true;
        } catch (IOException e) {
            log.warn("Failed to execute external command: {}", String.join(" ", command), e);
            return false;
        } catch (InterruptedException e) {
            log.warn("External command was interrupted: {}", String.join(" ", command), e);
            Thread.currentThread().interrupt();
            return false;
        }
    }

    abstract List<String> buildCommand(String target, String outputFilePath);

    abstract T parseOutput(String outputFilePath);

}

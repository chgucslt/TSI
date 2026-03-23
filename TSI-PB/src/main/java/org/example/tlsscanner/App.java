package org.example.tlsscanner;


import lombok.extern.slf4j.Slf4j;
import org.example.tlsscanner.api.Scanner;
import org.example.tlsscanner.config.ConfigurationManager;
import org.example.tlsscanner.tsi.TSIScanner;
import picocli.CommandLine;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;

@Slf4j
@CommandLine.Command(
        name = "TlsScanner",
        mixinStandardHelpOptions = true,
        version = "TlsScanner 1.0",
        description = "An active probing tool that identifies the type and version of TLS servers and analyzes homogeneity across multiple TLS servers."
)
public class App implements Callable<Integer> {

    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    @CommandLine.Option(
            names = {"--config"},
            description = "Path to custom configuration file to override default settings",
            paramLabel = "<config_file>"
    )
    private String configFile;


    @CommandLine.Parameters(
            paramLabel = "TARGET",
            description = "Target hosts in the format ip:port (e.g., 192.168.0.10:443)",
            arity = "1..*"
    )
    private List<String> targets;


    ConfigurationManager config;
    String scanID;


    public static void main(String[] args) {
        int exitCode = new CommandLine(new App())
                // 捕获参数解析异常（如缺少必需参数、参数格式错误等）
                .setParameterExceptionHandler((ex, args1) -> {
                    CommandLine cmd = ex.getCommandLine();
                    // 记录参数异常到日志文件
                    log.error("Parameter validation failed: {}", ex.getMessage());
                    // 打印错误信息到控制台
                    cmd.getErr().println(cmd.getColorScheme().errorText(ex.getMessage()));
                    // 当用户出现手误时，尝试提供建议（如拼写错误的选项、缺少参数等）
                    // 例如，用户将 --homogeneity 错误输为 --homogneity
                    // 此时，建议为：Possible solutions: --homogeneity
                    if (!CommandLine.UnmatchedArgumentException.printSuggestions(ex, cmd.getErr())) {
                        // 如果没有建议可提供，则打印完整的使用帮助信息
                        cmd.getErr().println();
                        cmd.usage(cmd.getErr());
                    }
                    return cmd.getCommandSpec().exitCodeOnInvalidInput();
                })
                // 捕获业务执行异常（如网络错误、分析失败等）
                .setExecutionExceptionHandler((ex, commandLine, parseResult) -> {
                    // 记录到日志文件，携带异常堆栈信息
                    log.error("Execution failed", ex);
                    // 打印干净的错误信息到控制台
                    commandLine.getErr().println(commandLine.getColorScheme().errorText(ex.getMessage()));
                    return commandLine.getCommandSpec().exitCodeOnExecutionException();
                })
                .execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        scanID = new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());

        log.info("Starting TLS Scanner with the following parameters:");
        log.info("Received targets: {}", targets);
        log.info("Config file: {}", configFile != null ? configFile : "Using default configuration");
        log.info("Scan ID: {}", scanID);

        // 初始化配置管理器
        initialize();

        // 开始指纹识别与同质性分析
        log.info("Starting TSI for targets: {}", targets);
        Scanner scanner = new TSIScanner(scanID, config, targets);
        scanner.start();


        return 0;
    }

    private void initialize() {
        this.config = ConfigurationManager.getInstance(configFile);
    }

}
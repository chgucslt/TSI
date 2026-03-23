package org.example.tlsscanner.config;

import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

@Slf4j
public class ConfigurationManager {

    // 默认的配置文件名
    private static final String DEFAULT_CONFIG_FILENAME = "config.properties";

    private static volatile ConfigurationManager instance;
    private final Properties properties;

    /**
     * 私有构造函数，先加载内置配置，再加载用户配置（如果提供）
     *
     * @param userConfigFile 用户提供的配置文件路径，可以为 null
     */
    private ConfigurationManager(String userConfigFile) {
        properties = new Properties();

        // 1. 首先加载系统内置的配置文件
        loadBuiltInConfig();

        // 2. 如果用户提供了配置文件，则加载并覆盖默认配置
        if (userConfigFile != null && !userConfigFile.isEmpty()) {
            loadUserConfig(userConfigFile);
        }
    }

    // 加载系统内置的配置文件（从 classpath 中加载）
    private void loadBuiltInConfig() {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(DEFAULT_CONFIG_FILENAME)) {
            if (is != null) {
                properties.load(is);
                log.info("Loaded built-in configuration: {}", DEFAULT_CONFIG_FILENAME);
            } else {
                log.error("Built-in configuration file not found: {}", DEFAULT_CONFIG_FILENAME);
                throw new IllegalStateException("Built-in configuration file not found: " + DEFAULT_CONFIG_FILENAME);
            }
        } catch (IOException e) {
            log.error("Failed to load built-in configuration: {}", e.getMessage());
            throw new IllegalStateException("Failed to load built-in configuration", e);
        }
    }

    // 加载用户提供的配置文件（从文件系统中加载），如果文件不存在则记录警告并继续使用默认配置
    private void loadUserConfig(String userConfigFile) {
        File file = new File(userConfigFile);
        if (!file.exists()) {
            log.warn("User configuration file not found: {}", userConfigFile);
            return;
        }

        try (InputStream is = new FileInputStream(file)) {
            properties.load(is);
            log.info("Loaded user configuration: {}", userConfigFile);
        } catch (IOException e) {
            log.error("Failed to load user configuration: {}", e.getMessage());
        }
    }

    /**
     * 获取 ConfigurationManager 的单例实例，如果用户提供了配置文件路径，则加载该配置文件覆盖默认配置
     *
     * @param userConfigFile 用户配置文件路径，可以为 null 或空字符串，表示不加载用户配置
     * @return ConfigurationManager 的单例实例
     */
    public static synchronized ConfigurationManager getInstance(String userConfigFile) {
        if (instance == null) {
            instance = new ConfigurationManager(userConfigFile);
        }
        return instance;
    }

    // 重置实例（仅用于测试）
    public static synchronized void resetInstance() {
        instance = null;
    }


    public String getProperty(String key) {
        return properties.getProperty(key);
    }

    public String getProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }

    public int getIntProperty(String key, int defaultValue) {
        String value = properties.getProperty(key);
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            log.warn("Invalid integer value for key '{}': {}", key, value);
            return defaultValue;
        }
    }

    public boolean getBooleanProperty(String key, boolean defaultValue) {
        String value = properties.getProperty(key);
        if (value == null) {
            return defaultValue;
        }
        return Boolean.parseBoolean(value.trim());
    }


    public String getProbesPath() {
        return getProperty("data.probes.path", "src/main/resources/probes.txt");
    }

    public String getFingerprintsPath() {
        return getProperty("data.fingerprints.path", "src/main/resources/fingerprints");
    }

    public String getMessagesPath() {
        return getProperty("data.messages.path", "src/main/resources/messages");
    }

    public String getCveDatabasePath() {
        return getProperty("data.cve.database.path", "src/main/resources/cves.sqlite");
    }

    public String getOutputDir() {
        return getProperty("output.dir", "output");
    }


    public int getSocketTimeout() {
        return getIntProperty("network.socket.timeout", 3000);
    }

    public int getSocketInterval() {
        return getIntProperty("network.socket.interval", 500);
    }

    public String getTlsCipherSuites() {
        return getProperty("tls.cipher_suites", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_RSA_WITH_AES_128_CBC_SHA TLS_RSA_WITH_3DES_EDE_CBC_SHA TLS_DHE_RSA_WITH_AES_128_CBC_SHA TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
    }

    public String getTlsVersion() {
        return getProperty("tls.version", "TLS12");
    }

    public String getTlsCompressionMethod() {
        return getProperty("tls.compression_method", "NULL");
    }

    public Double getSimilarityThreshold() {
        String value = getProperty("fingerprint.similarity.threshold", "0.0");
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException e) {
            System.err.println("Config key fingerprint.similarity.threshold is not a valid double (" + value + "). Using default: 0.0");
            return 0.0;
        }
    }

}

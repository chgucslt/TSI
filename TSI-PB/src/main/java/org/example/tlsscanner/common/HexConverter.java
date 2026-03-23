package org.example.tlsscanner.common;

public class HexConverter {

    private static String CHARS = "0123456789ABCDEF";

    public static String bytesToHex(byte[] bytes) {
        StringBuffer hex = new StringBuffer();

        for (int i = 0; i < bytes.length; i++) {
            // 通过位运算获取每个字节的高4位，并转换为对应的十六进制字符
            int n1 = (bytes[i] >> 4) & 0x0F;
            hex.append(CHARS.charAt(n1));
            // 通过位运算获取每个字节的低4位，并转换为对应的十六进制字符
            int n2 = bytes[i] & 0x0F;
            hex.append(CHARS.charAt(n2));
        }

        return hex.toString();
    }

    public static byte[] hexToBytes(String hex) {
        // TODO：检查字符串是否是合法的十六进制字符串（只包含0-9和A-F/a-f）

        // 如果十六进制字符串的长度是奇数，在前面补一个0，使其成为偶数长度
        if (hex.length() % 2 != 0) hex = "0" + hex;

        // 创建一个字节数组，长度是十六进制字符串长度的一半，因为每两个十六进制字符表示一个字节
        byte[] bytes = new byte[hex.length() / 2];

        // 遍历十六进制字符串，每两个字符转换为一个字节
        for (int i = 0; i < hex.length(); i = i + 2) {
            // 使用 Integer.decode 将十六进制字符串转换为整数，然后获取其字节值
            bytes[i / 2] = Integer.decode("0x" + hex.substring(i, i + 2)).byteValue();
        }

        return bytes;
    }
}

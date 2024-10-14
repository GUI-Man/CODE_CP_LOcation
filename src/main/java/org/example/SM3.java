package org.example;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.Arrays;

public class SM3 {
    public static byte[] sm3Hash(byte[] data) {
        SM3Digest digest = new SM3Digest(); // 创建SM3Digest实例
        digest.update(data, 0, data.length); // 将数据输入到SM3算法中
        byte[] hash = new byte[digest.getDigestSize()]; // 创建存放结果的字节数组
        digest.doFinal(hash, 0); // 完成哈希操作，结果存入hash
        return hash; // 返回哈希结果
    }
    // 扩展哈希，生成指定长度的哈希值
    public static byte[] extendHash(byte[] initialHash, int requiredLength) {
        // 确保所需长度大于初始哈希值的长度
        if (requiredLength <= initialHash.length) {
            return Arrays.copyOf(initialHash, requiredLength);
        }

        // 创建一个缓冲区来存储最终的哈希值
        byte[] extendedHash = new byte[requiredLength];

        // 将初始哈希值复制到缓冲区的开头
        System.arraycopy(initialHash, 0, extendedHash, 0, initialHash.length);

        // 当前生成的哈希长度
        int currentLength = initialHash.length;
        byte[] currentInput = initialHash;

        // 不断计算新的哈希值，直到满足所需长度
        while (currentLength < requiredLength) {
            // 计算上一次哈希结果的哈希值
            byte[] nextHash = sm3Hash(currentInput);

            // 确定要复制的字节数
            int bytesToCopy = Math.min(nextHash.length, requiredLength - currentLength);

            // 将新的哈希值复制到扩展哈希的缓冲区
            System.arraycopy(nextHash, 0, extendedHash, currentLength, bytesToCopy);

            // 更新当前哈希长度和输入
            currentLength += bytesToCopy;
            currentInput = nextHash;
        }

        return extendedHash;
    }
}

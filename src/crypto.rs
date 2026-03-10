//! 加密与校验模块 (Cryptography & Checksum)
//!
//! 本模块实现了 Dr.COM 协议中特有的各种算法，包括自定义校验和、密码混淆以及标准哈希。
//! 算法实现遵循原版协议逻辑，确保字节序列与服务器端完全对齐。

use md5::{Digest, Md5};
use tracing::trace;

/// 计算 Dr.COM D系列协议专用的 4 字节校验和 (CRC-1968)
///
/// 该算法将输入数据按 4 字节为一组（小端序）进行异或累加，最后乘以魔数 1968。
/// 如果数据长度不是 4 的倍数，末尾不足部分将以 `0x00` 填充。
///
/// ### 数学表达
/// $$Checksum = (\bigoplus_{i=0}^{n} Chunk_i) \times 1968 \pmod{2^{32}}$$
///
/// ### 参数
/// * `data`: 待计算的原始字节序列
#[inline]
pub fn checksum_d_series(data: &[u8]) -> [u8; 4] {
    let mut ret: u32 = 1234;
    let multiplier: u32 = 1968;

    // data.chunks(4) 会自动将数据按 4 字节切片
    for chunk in data.chunks(4) {
        let mut buf = [0u8; 4];
        let len = chunk.len();
        buf[..len].copy_from_slice(chunk);

        // 从小端序字节数组解析为 u32
        let val = u32::from_le_bytes(buf);
        ret ^= val;
    }

    // 使用 wrapping_mul 防止溢出时的运行时恐慌
    ret = ret.wrapping_mul(multiplier);

    let result = ret.to_le_bytes();
    trace!("D-Series Checksum 计算完成: {:02X?}", result);
    result
}

/// 循环异或加密 (ROR - Rotate Right)
///
/// Dr.COM 经典的密码混淆算法。将字节与 Key 异或后，进行 5 位的循环右移。
///
///
///
/// ### 算法逻辑
/// 1. 取出数据字节 $d$ 和对应的密钥字节 $k$
/// 2. 计算 $x = d \oplus k$
/// 3. 将 $x$ 循环右移 5 位
///
/// ### 参数
/// * `data`: 原始数据（如明文密码）
/// * `key`: 密钥序列
#[inline]
pub fn ror_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ret = Vec::with_capacity(data.len());
    let key_len = key.len();

    if key_len == 0 {
        trace!("ROR 加密跳过：密钥为空");
        return data.to_vec();
    }

    for (i, &byte) in data.iter().enumerate() {
        let k = key[i % key_len];
        let x = byte ^ k;

        // Rust 原生支持 u8 的循环右移
        let val = x.rotate_right(5);
        ret.push(val);
    }

    trace!("ROR 加密完成，输出长度: {} 字节", ret.len());
    ret
}

/// Dr.COM 自定义 CRC32 变体算法
///
/// 主要用于 P 版 (PPPoE) 心跳包或部分 D 版扩展字段的校验。
///
/// ### 参数
/// * `data`: 待校验数据
/// * `init`: 初始向量 (IV)
#[inline]
pub fn drcom_crc32(data: &[u8], init: u32) -> u32 {
    let mut ret = init;

    for chunk in data.chunks(4) {
        let mut buf = [0u8; 4];
        let len = chunk.len();
        buf[..len].copy_from_slice(chunk);

        let val = u32::from_le_bytes(buf);
        ret ^= val;
    }

    trace!("Custom CRC32 计算结果: 0x{:08X}", ret);
    ret
}

/// 计算 MD5 哈希的快捷函数
///
/// 返回标准的 16 字节原始哈希数组。
#[inline]
pub fn md5_bytes(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    let hash = hasher.finalize().into();
    trace!("MD5 计算完成 (输入长度: {} 字节)", data.len());
    hash
}

// ------------------------------------------------------------------------
// 单元测试
// ------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ror_encrypt() {
        let data = b"hello";
        let key = b"key";
        let encrypted = ror_encrypt(data, key);
        assert_eq!(encrypted.len(), 5);
        // 验证非空性
        assert_ne!(encrypted, data.to_vec());
    }

    #[test]
    fn test_md5() {
        let data = b"drcom";
        let hash = md5_bytes(data);
        assert_eq!(hash.len(), 16);
        // 校验 drcom 的典型哈希开头
        assert_eq!(hash[0], 0x3b);
    }
}

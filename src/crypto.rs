use md5::{Digest, Md5};

/// 计算 Dr.COM D系列协议专用的 4 字节校验和 (CRC-1968)。
pub fn checksum_d_series(data: &[u8]) -> [u8; 4] {
    let mut ret: u32 = 1234;
    let multiplier: u32 = 1968;

    // data.chunks(4) 会自动将数据按 4 字节切片
    for chunk in data.chunks(4) {
        let mut buf = [0u8; 4]; // 默认全 0
        let len = chunk.len();
        buf[..len].copy_from_slice(chunk);

        // 从小端序字节数组解析为 u32
        let val = u32::from_le_bytes(buf);
        ret ^= val;
    }

    // Rust 优雅的 `wrapping_mul` (溢出截断乘法)
    ret = ret.wrapping_mul(multiplier);

    // 转换回小端序字节数组
    ret.to_le_bytes()
}

/// 循环异或加密 (ROR - Rotate Right)。
/// Dr.COM 用于对密码字段进行混淆。
pub fn ror_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ret = Vec::with_capacity(data.len());
    let key_len = key.len();

    // 防御性编程：防止除零崩溃
    if key_len == 0 {
        return data.to_vec();
    }

    for (i, &byte) in data.iter().enumerate() {
        let k = key[i % key_len];
        let x = byte ^ k;

        let val = x.rotate_right(5);
        ret.push(val);
    }

    ret
}

/// Dr.COM 自定义的 CRC32 算法。
/// 常见于 P 版 (PPPoE) 心跳包的校验。
pub fn drcom_crc32(data: &[u8], init: u32) -> u32 {
    let mut ret = init;

    for chunk in data.chunks(4) {
        let mut buf = [0u8; 4];
        let len = chunk.len();
        buf[..len].copy_from_slice(chunk);

        let val = u32::from_le_bytes(buf);
        ret ^= val;
    }

    ret
}

/// 计算 MD5 哈希的快捷函数。
pub fn md5_bytes(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    // finalize() 返回 GenericArray，into() 自动转换为 [u8; 16]
    hasher.finalize().into()
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
    }

    #[test]
    fn test_md5() {
        let data = b"drcom";
        let hash = md5_bytes(data);
        assert_eq!(hash.len(), 16);
    }
}

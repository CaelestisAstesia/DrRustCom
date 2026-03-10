//! 报文构造与解析模块 (Packet Construction & Parsing)
//!
//! 本模块实现了 Dr.COM 5.2.0(D) 协议的所有二进制封包逻辑。
//! 包含 Challenge (握手)、Login (登录)、Keep-Alive (心跳) 以及 Logout (注销) 的完整报文结构实现。
//! 所有的字节序 (Endianness) 均严格遵循原版协议定义。

use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, trace};
use crate::config::DrcomConfig;
use crate::crypto::{checksum_d_series, md5_bytes};
use super::constant::*;

/// 对字符串进行字节编码并填充至指定长度
///
/// 如果原字符串超出长度则截断，不足则在尾部填充 `0x00`。
fn encode_and_pad(s: &str, max_len: usize) -> Vec<u8> {
    let mut bytes = s.as_bytes().to_vec();
    bytes.truncate(max_len);
    if bytes.len() < max_len {
        bytes.resize(max_len, 0x00);
    }
    bytes
}

// =========================================================================
// Challenge (阶段 1: 握手)
// =========================================================================

/// 构建 Challenge 请求报文 (0x01 0x02)
///
/// 用于向服务器请求 Salt (盐值)，开启认证流程。
///
/// ### 参数
/// * `padding`: 15 字节的填充数据，通常基于协议版本标识
pub fn build_challenge_request(padding: &[u8; 15]) -> Vec<u8> {
    trace!("正在构造 Challenge 请求数据包...");
    let rand_val: u64 = 0x0f + (rand::random::<u16>() % (0xff - 0x0f + 1)) as u64;
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // 精确复刻 Python 版的种子计算逻辑: (int(t) + rand) % 0xFFFF
    let seed = ((t + rand_val) % 0xFFFF) as u16;

    let mut pkt = Vec::with_capacity(20);
    pkt.extend_from_slice(CHALLENGE_REQ);
    pkt.extend_from_slice(&seed.to_le_bytes()); // 2 字节小端序种子
    pkt.push(0x09);
    pkt.extend_from_slice(padding);

    trace!(seed = seed, "Challenge 请求构造完成");
    pkt
}

/// 解析 Challenge 响应报文
///
/// 从服务器返回的 0x02 报文中提取 4 字节的 Salt。
pub fn parse_challenge_response(data: &[u8]) -> Option<[u8; 4]> {
    if data.len() >= SALT_OFFSET_END && data[0] == CHALLENGE_RESP {
        let mut salt = [0u8; 4];
        salt.copy_from_slice(&data[SALT_OFFSET_START..SALT_OFFSET_END]);
        debug!(salt = ?salt, "解析成功：获取到服务器 Salt");
        return Some(salt);
    }
    debug!("Challenge 响应解析失败：数据长度不足或包头不匹配");
    None
}

// =========================================================================
// Login (阶段 2: 认证)
// =========================================================================

/// 构建 Login 登录请求报文 (0x03 0x01)
///
/// 这是最复杂的报文，包含了 MD5 哈希链、MAC 地址混淆以及多段系统指纹。
///
///
///
/// ### 参数
/// * `config`: 包含用户凭据与环境指纹的配置对象
/// * `salt`: 从 Challenge 阶段获得的 4 字节盐值
pub fn build_login_packet(config: &DrcomConfig, salt: &[u8; 4]) -> Vec<u8> {
    debug!("开始构造登录认证数据包...");
    let usr_padded = encode_and_pad(&config.username, USERNAME_MAX_LEN);
    let pwd_bytes = config.password.as_bytes();
    let mut pkt = Vec::with_capacity(350);

    // 1. Header (4 Bytes)
    pkt.extend_from_slice(LOGIN_REQ);
    pkt.push(0x00);
    pkt.push((20 + config.username.len()) as u8);

    // 2. MD5_A (16 Bytes): h(0x03, 0x01, salt, password)
    let mut md5a_input = Vec::new();
    md5a_input.extend_from_slice(MD5_SALT_PREFIX);
    md5a_input.extend_from_slice(salt);
    md5a_input.extend_from_slice(pwd_bytes);
    let md5a = md5_bytes(&md5a_input);
    pkt.extend_from_slice(&md5a);
    trace!("MD5_A 计算完成");

    // 3. Identity & Control (Username + Status + AdapterNum)
    pkt.extend_from_slice(&usr_padded);
    pkt.extend_from_slice(&config.control_check_status);
    pkt.extend_from_slice(&config.adapter_num);

    // 4. MAC XOR (6 Bytes): 将物理地址与 MD5_A 进行按位异或混淆
    let mut mac_xor = [0u8; 6];
    for i in 0..6 { mac_xor[i] = config.mac_address[i] ^ md5a[i]; }
    pkt.extend_from_slice(&mac_xor);

    // 5. MD5_B (16 Bytes): h(0x01, password, salt, 0x00...)
    let mut md5b_input = Vec::new();
    md5b_input.push(MD5B_SALT_PREFIX);
    md5b_input.extend_from_slice(pwd_bytes);
    md5b_input.extend_from_slice(salt);
    md5b_input.extend_from_slice(MD5B_SALT_SUFFIX);
    pkt.extend_from_slice(&md5_bytes(&md5b_input));
    trace!("MD5_B 计算完成");

    // 6. IP List & MD5_C (8 Bytes)
    let mut ip_section = Vec::new();
    ip_section.push(0x01); // IP 数量
    ip_section.extend_from_slice(&config.host_ip.octets());
    ip_section.extend_from_slice(&[0u8; 12]); // 占位
    pkt.extend_from_slice(&ip_section);

    let mut md5c_input = ip_section.clone();
    md5c_input.extend_from_slice(MD5C_SUFFIX);
    pkt.extend_from_slice(&md5_bytes(&md5c_input)[..LOGIN_MD5C_LEN]);

    // 7. IPDOG (用于某些版本的指纹验证)
    pkt.extend_from_slice(&config.ipdog);
    pkt.extend_from_slice(&config.padding_after_ipdog);

    // 8. Host Info (Hostname + DNS + DHCP)
    pkt.extend_from_slice(&encode_and_pad(&config.host_name, HOSTNAME_MAX_LEN));
    pkt.extend_from_slice(&config.primary_dns.octets());
    pkt.extend_from_slice(&config.dhcp_server.octets());
    pkt.extend_from_slice(&config.secondary_dns.octets());
    pkt.extend_from_slice(&config.padding_after_dhcp);

    // 9. OS Info & Padding
    pkt.extend_from_slice(&config.os_info_bytes);
    pkt.extend_from_slice(&encode_and_pad(&config.host_os, HOST_OS_MAX_LEN));
    pkt.extend_from_slice(&[0u8; HOST_OS_SUFFIX_LEN]);

    // 10. Version Fingerprint
    pkt.extend_from_slice(&config.auth_version);

    // 11. Checksum (4 Bytes): 针对已拼好的报文进行 CRC 校验
    let mut chk_input = pkt.clone();
    chk_input.extend_from_slice(CHECKSUM_SUFFIX);
    chk_input.extend_from_slice(&config.mac_address);
    let checksum_val = checksum_d_series(&chk_input);

    // 12. Auth Ext Data
    pkt.push(AUTH_EXT_CODE);
    pkt.push(AUTH_EXT_LEN);
    pkt.extend_from_slice(&checksum_val);
    pkt.extend_from_slice(AUTH_EXT_OPTION);
    pkt.extend_from_slice(&config.mac_address);

    // 13. Final Padding & Random Tail (2 Bytes)
    pkt.extend_from_slice(&config.padding_auth_ext);
    let rnd_tail: [u8; 2] = rand::random();
    pkt.extend_from_slice(&rnd_tail);

    debug!(len = pkt.len(), "登录认证数据包构造完成");
    pkt
}

/// 解析 Login 响应报文
///
/// ### 返回
/// 元组: `(是否成功, 可选的 Auth Info 凭证, 可选的错误代码)`
pub fn parse_login_response(data: &[u8]) -> (bool, Option<[u8; 16]>, Option<u8>) {
    if data.is_empty() { return (false, None, None); }

    if data[0] == LOGIN_RESP_SUCC && data.len() >= AUTH_INFO_END {
        let mut auth = [0u8; 16];
        auth.copy_from_slice(&data[AUTH_INFO_START..AUTH_INFO_END]);
        (true, Some(auth), None)
    } else if data[0] == LOGIN_RESP_FAIL {
        let err = if data.len() > ERROR_CODE_INDEX { Some(data[ERROR_CODE_INDEX]) } else { Some(0) };
        (false, None, err)
    } else {
        (false, None, None)
    }
}

// =========================================================================
// Keep-Alive (阶段 3: 保活)
// =========================================================================

/// 构建心跳类型 1 请求 (0xFF)
///
/// 携带 MD5 混淆的时间戳与认证凭证。
pub fn build_keep_alive1_packet(salt: &[u8; 4], pwd: &str, auth_info: &[u8; 16]) -> Vec<u8> {
    trace!("正在构造 KA1 (0xFF) 心跳包...");
    let mut md5_input = Vec::new();
    md5_input.extend_from_slice(MD5_SALT_PREFIX);
    md5_input.extend_from_slice(salt);
    md5_input.extend_from_slice(pwd.as_bytes());
    let md5_hash = md5_bytes(&md5_input);

    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let timestamp = (t % 0xFFFF) as u16;

    let mut pkt = Vec::with_capacity(64);
    pkt.push(KEEP_ALIVE_1);
    pkt.extend_from_slice(&md5_hash);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
    pkt.extend_from_slice(auth_info);
    pkt.extend_from_slice(&timestamp.to_be_bytes()); // 注意：此处时间戳通常为大端序
    pkt.extend_from_slice(&[0u8; 4]);
    pkt
}

/// 解析心跳类型 1 的响应包头
pub fn parse_keep_alive1_response(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == MISC
}

/// 构建心跳类型 2 请求 (0x07)
///
/// 该包负责上报 IP 地址与客户端版本，其内部含有 `Type 1` 或 `Type 3` 子包。
///
/// ### 参数
/// * `num`: 循环序列号 (0-255)
/// * `tail`: 上一次收到的服务器尾部验证数据
/// * `p_type`: 心跳子类型 (1 或 3)
pub fn build_keep_alive2_packet(num: u8, tail: &[u8; 4], p_type: u8, config: &DrcomConfig, is_first: bool) -> Vec<u8> {
    trace!(seq = num, t = p_type, "正在构造 KA2 (0x07) 心跳包...");
    let mut pkt = Vec::with_capacity(64);
    pkt.push(MISC);
    pkt.push(num);
    pkt.extend_from_slice(KA2_HEADER_PREFIX);
    pkt.push(p_type);

    if is_first {
        pkt.extend_from_slice(&[0x0f, 0x27]); // 特殊初始化魔数
    } else {
        pkt.extend_from_slice(&config.keep_alive_version);
    }

    pkt.extend_from_slice(KA2_FIXED_PART1);
    pkt.extend_from_slice(&[0u8; 6]);
    pkt.extend_from_slice(tail);
    pkt.extend_from_slice(&[0u8; 4]);

    if p_type == 3 {
        pkt.extend_from_slice(&[0u8; 4]);
        pkt.extend_from_slice(&config.host_ip.octets());
        pkt.extend_from_slice(&[0u8; 8]);
    } else {
        pkt.extend_from_slice(&[0u8; 16]);
    }
    pkt
}

/// 解析心跳 2 响应报文
///
/// 提取服务器返回的下一次发包所需的 4 字节 Tail。
pub fn parse_keep_alive2_response(data: &[u8]) -> Option<[u8; 4]> {
    if data.len() >= 20 && data[0] == MISC {
        let mut tail = [0u8; 4];
        tail.copy_from_slice(&data[16..20]);
        return Some(tail);
    }
    None
}

// =========================================================================
// Logout (注销)
// =========================================================================

/// 构建注销请求报文 (0x06)
pub fn build_logout_packet(config: &DrcomConfig, salt: &[u8; 4], auth_info: &[u8; 16]) -> Vec<u8> {
    debug!("正在构造注销请求数据包...");
    let pwd_bytes = config.password.as_bytes();
    let mut pkt = Vec::with_capacity(80);

    pkt.push(LOGOUT_REQ);
    pkt.push(LOGOUT_TYPE);
    pkt.push(0x00);
    pkt.push((20 + config.username.len()) as u8);

    let mut md5_input = Vec::new();
    md5_input.extend_from_slice(MD5_SALT_PREFIX);
    md5_input.extend_from_slice(salt);
    md5_input.extend_from_slice(pwd_bytes);
    let md5a = md5_bytes(&md5_input);
    pkt.extend_from_slice(&md5a);

    pkt.extend_from_slice(&encode_and_pad(&config.username, USERNAME_MAX_LEN));
    pkt.extend_from_slice(&config.control_check_status);
    pkt.extend_from_slice(&config.adapter_num);

    let mut mac_xor = [0u8; 6];
    for i in 0..6 { mac_xor[i] = config.mac_address[i] ^ md5a[i]; }
    pkt.extend_from_slice(&mac_xor);
    pkt.extend_from_slice(auth_info);

    pkt
}

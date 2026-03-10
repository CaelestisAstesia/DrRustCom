//! Dr.COM 5.2.0(D) 协议族常量表 (Constants)
//! 仅定义协议的结构性常量（如 OpCode、偏移量、魔数）。

// =========================================================================
// 协议操作码 (Protocol Codes)
// =========================================================================

/// 挑战请求 (Client -> Server)
pub const CHALLENGE_REQ: &[u8; 2] = b"\x01\x02";
/// 挑战响应 (Server -> Client)
pub const CHALLENGE_RESP: u8 = 0x02;
/// 登录请求 (Client -> Server)
pub const LOGIN_REQ: &[u8; 2] = b"\x03\x01";
/// 登录成功响应
pub const LOGIN_RESP_SUCC: u8 = 0x04;
/// 登录失败响应
pub const LOGIN_RESP_FAIL: u8 = 0x05;
/// 注销请求
pub const LOGOUT_REQ: u8 = 0x06;
/// 注销类型
pub const LOGOUT_TYPE: u8 = 0x01;
/// 杂项/心跳2 (KA2)
pub const MISC: u8 = 0x07;
/// 心跳1 (KA1)
pub const KEEP_ALIVE_1: u8 = 0xff;

// =========================================================================
// 结构偏移量 (Offsets & Structure)
// =========================================================================

// Challenge 响应
pub const SALT_OFFSET_START: usize = 4;
pub const SALT_OFFSET_END: usize = 8;

// Login 核心结构长度
pub const LOGIN_MD5A_LEN: usize = 16;
pub const LOGIN_MD5B_LEN: usize = 16;
pub const LOGIN_MD5C_LEN: usize = 8;
pub const LOGIN_MAC_XOR_LEN: usize = 6;

// Login 填充对齐长度 (用于按长度截断/填充)
pub const USERNAME_MAX_LEN: usize = 36;
pub const HOSTNAME_MAX_LEN: usize = 32;
pub const HOST_OS_MAX_LEN: usize = 32;
pub const HOST_OS_SUFFIX_LEN: usize = 96;

// 响应包解析
pub const AUTH_INFO_START: usize = 23;
pub const AUTH_INFO_END: usize = 39;
pub const AUTH_INFO_LEN: usize = 16;
pub const ERROR_CODE_INDEX: usize = 4; // 0x05 包中错误码的位置

// =========================================================================
// 算法魔法数字 (Magic Numbers for Algorithms)
// =========================================================================

// MD5 计算辅助
pub const MD5_SALT_PREFIX: &[u8; 2] = b"\x03\x01";
pub const MD5B_SALT_PREFIX: u8 = 0x01;
pub const MD5B_SALT_SUFFIX: &[u8; 4] = b"\x00\x00\x00\x00";
pub const MD5C_SUFFIX: &[u8; 4] = b"\x14\x00\x07\x0b";

// Checksum 计算辅助
pub const CHECKSUM_SUFFIX: &[u8; 6] = b"\x01\x26\x07\x11\x00\x00";

// 扩展数据段 (Auth Ext Data) 头部
pub const AUTH_EXT_CODE: u8 = 0x02;
pub const AUTH_EXT_LEN: u8 = 0x0c;
pub const AUTH_EXT_OPTION: &[u8; 2] = b"\x00\x00";

// Keep Alive 2 (0x07)
pub const KA2_HEADER_PREFIX: &[u8; 3] = b"\x28\x00\x0b";
pub const KA2_FIXED_PART1: &[u8; 2] = b"\x2f\x12";

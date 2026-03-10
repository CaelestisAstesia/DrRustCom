//! Dr.COM 5.2.0(D) 协议族常量表 (Constants)
//!
//! 本模块定义了 D 版协议在网络交互中使用的所有静态结构，
//! 包括操作码 (OpCodes)、字段偏移量、长度限制以及用于校验和计算的魔数因子。
//! 所有数值均严格对齐自原版 Python 实现，确保二进制兼容性。

// =========================================================================
// 协议操作码 (Protocol Codes)
// =========================================================================



/// 挑战请求头 (Client -> Server): 对应 Python 中的 `\x01\x02`
pub const CHALLENGE_REQ: &[u8; 2] = b"\x01\x02";
/// 挑战响应头 (Server -> Client): 服务器下发 Salt 时的起始包头
pub const CHALLENGE_RESP: u8 = 0x02;

/// 登录请求头 (Client -> Server): 对应 Python 中的 `\x03\x01`
pub const LOGIN_REQ: &[u8; 2] = b"\x03\x01";
/// 登录成功响应头: 表示认证通过
pub const LOGIN_RESP_SUCC: u8 = 0x04;
/// 登录失败响应头: 后续偏移量 [`ERROR_CODE_INDEX`] 处将包含错误码
pub const LOGIN_RESP_FAIL: u8 = 0x05;

/// 注销请求头: 主动断开连接
pub const LOGOUT_REQ: u8 = 0x06;
/// 注销类型子码
pub const LOGOUT_TYPE: u8 = 0x01;

/// 杂项/心跳类型 2 (KA2): 处理 0x07 系列包，通常包含 IP 和版本指纹
pub const MISC: u8 = 0x07;
/// 心跳类型 1 (KA1): 0xFF 系列包，用于周期性身份维持
pub const KEEP_ALIVE_1: u8 = 0xff;

// =========================================================================
// 结构偏移量与长度 (Offsets & Structure)
// =========================================================================

/// Challenge 响应中 Salt 盐值的起始偏移量
pub const SALT_OFFSET_START: usize = 4;
/// Challenge 响应中 Salt 盐值的截止偏移量 (4 字节长度)
pub const SALT_OFFSET_END: usize = 8;

/// Login 流程中第一段 MD5 (MD5_A) 的预期长度
pub const LOGIN_MD5A_LEN: usize = 16;
/// Login 流程中第二段 MD5 (MD5_B) 的预期长度
pub const LOGIN_MD5B_LEN: usize = 16;
/// Login 流程中第三段 MD5 (MD5_C) 截断后的长度
pub const LOGIN_MD5C_LEN: usize = 8;
/// 物理地址混淆后的长度
pub const LOGIN_MAC_XOR_LEN: usize = 6;

/// 用户名最大填充长度 (36 字节)
pub const USERNAME_MAX_LEN: usize = 36;
/// 主机名最大填充长度 (32 字节)
pub const HOSTNAME_MAX_LEN: usize = 32;
/// 操作系统描述最大填充长度 (32 字节)
pub const HOST_OS_MAX_LEN: usize = 32;
/// 操作系统信息扩展段的后缀填充长度
pub const HOST_OS_SUFFIX_LEN: usize = 96;

/// 登录成功包中 `Auth Info` 凭证的起始位置
pub const AUTH_INFO_START: usize = 23;
/// 登录成功包中 `Auth Info` 凭证的终止位置
pub const AUTH_INFO_END: usize = 39;
/// `Auth Info` 凭证的标准长度
pub const AUTH_INFO_LEN: usize = 16;

/// 在登录失败 (0x05) 包中，具体失败原因代码所在的字节索引
pub const ERROR_CODE_INDEX: usize = 4;

// =========================================================================
// 算法魔法数字 (Magic Numbers for Algorithms)
// =========================================================================

/// 计算 Login MD5 时使用的静态前缀
pub const MD5_SALT_PREFIX: &[u8; 2] = b"\x03\x01";
/// 计算 MD5_B 时的类型前缀
pub const MD5B_SALT_PREFIX: u8 = 0x01;
/// 计算 MD5_B 时的 4 字节零填充后缀
pub const MD5B_SALT_SUFFIX: &[u8; 4] = b"\x00\x00\x00\x00";
/// 计算 MD5_C 时的特定协议混淆后缀
pub const MD5C_SUFFIX: &[u8; 4] = b"\x14\x00\x07\x0b";

/// 计算 D 系列 Checksum 时，在 MAC 地址前追加的固定干扰序列
pub const CHECKSUM_SUFFIX: &[u8; 6] = b"\x01\x26\x07\x11\x00\x00";

/// 扩展数据段 (Auth Ext Data) 的头部标识码
pub const AUTH_EXT_CODE: u8 = 0x02;
/// 扩展数据段的固定载荷长度
pub const AUTH_EXT_LEN: u8 = 0x0c;
/// 扩展数据段的占位选项
pub const AUTH_EXT_OPTION: &[u8; 2] = b"\x00\x00";

// --- Keep Alive 2 (0x07) 专用魔数 ---

/// 心跳 2 包头的固定前缀标识
pub const KA2_HEADER_PREFIX: &[u8; 3] = b"\x28\x00\x0b";
/// 心跳 2 中用于标识协议特征的固定载荷
pub const KA2_FIXED_PART1: &[u8; 2] = b"\x2f\x12";

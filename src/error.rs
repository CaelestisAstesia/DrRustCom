use thiserror::Error;

/// 为整个库提供便利的 Result 类型别名
pub type Result<T> = std::result::Result<T, DrcomError>;

/// Dr.COM 核心库的全局异常枚举
#[derive(Debug, Error)]
pub enum DrcomError {
    #[error("配置错误: {0}")]
    Config(String),

    #[error("网络错误: {0}")]
    Network(String),

    #[error("协议交互异常: {0}")]
    Protocol(String),

    #[error("状态机错误: {0}")]
    State(String),

    // 要求 AuthErrorCode 必须实现 std::error::Error，我们在下面满足它
    #[error("认证被拒绝: {0}")]
    Auth(#[from] AuthErrorCode),
}

/// Dr.COM 认证失败错误代码枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthErrorCode {
    #[error("账号已在别处登录 (有线)")]
    InUseWired,
    #[error("服务器繁忙，请稍后重试")]
    ServerBusy,
    #[error("账号或密码错误")]
    WrongPassword,
    #[error("账户余额不足或时长超限")]
    InsufficientFunds,
    #[error("账号已暂停使用")]
    AccountFrozen,
    #[error("IP地址不匹配 (请检查是否获取到了正确的内网IP)")]
    WrongIp,
    #[error("MAC地址不匹配")]
    WrongMac,
    #[error("在线IP数量超出限制")]
    TooManyIp,
    #[error("客户端版本过低或账号被封禁")]
    WrongVersion,
    #[error("IP/MAC 绑定错误")]
    WrongIpMacBind,
    #[error("检测到静态IP，请改为自动获取 (DHCP)")]
    ForceDhcp,
    #[error("未知认证错误 (Code: {0:#04x})")]
    Unknown(u8),
}

// 实现从 u8 到 AuthErrorCode 的安全转换 (替代原来的显式赋值)
impl From<u8> for AuthErrorCode {
    fn from(code: u8) -> Self {
        match code {
            0x01 => Self::InUseWired,
            0x02 => Self::ServerBusy,
            0x03 => Self::WrongPassword,
            0x04 => Self::InsufficientFunds,
            0x05 => Self::AccountFrozen,
            0x07 => Self::WrongIp,
            0x0B => Self::WrongMac,
            0x14 => Self::TooManyIp,
            0x15 => Self::WrongVersion,
            0x16 => Self::WrongIpMacBind,
            0x17 => Self::ForceDhcp,
            _ => Self::Unknown(code),
        }
    }
}

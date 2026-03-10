//! 错误处理模块 (Error Handling)
//!
//! 本模块定义了 Dr.COM 核心库中所有可能的异常情况。
//! 采用 `thiserror` 框架实现自动化的错误描述生成，并提供强类型的认证错误码映射。

use thiserror::Error;
use tracing::error;

/// 为整个库提供便利的 Result 类型别名
///
/// 默认使用 [`DrcomError`] 作为错误类型。
pub type Result<T> = std::result::Result<T, DrcomError>;

/// Dr.COM 核心库的全局异常枚举
///
/// 该枚举涵盖了从配置加载到网络传输，再到协议状态机的全生命周期错误。
#[derive(Debug, Error)]
pub enum DrcomError {
    /// 配置文件读取或解析失败
    #[error("配置错误: {0}")]
    Config(String),

    /// 底层 UDP 套接字或 IO 操作异常
    #[error("网络错误: {0}")]
    Network(String),

    /// 接收到的数据包不符合协议规范（如校验和失败、长度错误）
    #[error("协议交互异常: {0}")]
    Protocol(String),

    /// 非法的状态转换（例如在未登录状态下尝试心跳）
    #[error("状态机错误: {0}")]
    State(String),

    /// 认证过程被服务器明确拒绝
    ///
    /// 该变体由 [`AuthErrorCode`] 自动转换而来，包含了服务器返回的业务级错误原因。
    #[error("认证被拒绝: {0}")]
    Auth(#[from] AuthErrorCode),
}

/// Dr.COM 认证失败错误代码枚举 (业务级错误)
///
/// 对应服务器返回包中偏移量为 4 的错误字节。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthErrorCode {
    /// 代码: 0x01 - 账号已在其它有线终端登录
    #[error("账号已在别处登录 (有线)")]
    InUseWired,

    /// 代码: 0x02 - 服务器并发处理达到上限
    #[error("服务器繁忙，请稍后重试")]
    ServerBusy,

    /// 代码: 0x03 - 用户凭据无效
    #[error("账号或密码错误")]
    WrongPassword,

    /// 代码: 0x04 - 欠费或套餐流量已耗尽
    #[error("账户余额不足或时长超限")]
    InsufficientFunds,

    /// 代码: 0x05 - 账号处于封禁或暂停状态
    #[error("账号已暂停使用")]
    AccountFrozen,

    /// 代码: 0x07 - 配置中的内网 IP 与网关检测到的不符
    #[error("IP 地址不匹配 (请检查是否获取到了正确的内网 IP)")]
    WrongIp,

    /// 代码: 0x0B - 物理地址校验失败
    #[error("MAC 地址不匹配")]
    WrongMac,

    /// 代码: 0x14 - 超过该账号允许的最大在线终端数
    #[error("在线 IP 数量超出限制")]
    TooManyIp,

    /// 代码: 0x15 - 账号被限制登录或客户端指纹不合规
    #[error("客户端版本过低或账号被封禁")]
    WrongVersion,

    /// 代码: 0x16 - 该账号开启了静态 IP/MAC 绑定
    #[error("IP/MAC 绑定错误")]
    WrongIpMacBind,

    /// 代码: 0x17 - 强制要求使用 DHCP 获取地址
    #[error("检测到静态 IP，请改为自动获取 (DHCP)")]
    ForceDhcp,

    /// 未在已知列表中的错误码
    #[error("未知认证错误 (Code: {0:#04x})")]
    Unknown(u8),
}

// 实现从原始字节到强类型错误码的转换
impl From<u8> for AuthErrorCode {
    /// 将服务器返回的原始字节转换为对应的错误枚举
    ///
    ///
    fn from(code: u8) -> Self {
        let err = match code {
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
            _ => {
                // 对于未知错误，记录一条警告日志
                error!("接收到未知的认证错误码: {:#04x}", code);
                Self::Unknown(code)
            }
        };
        err
    }
}

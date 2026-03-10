//! 配置模块 (Configuration)
//!
//! 本模块负责处理 Dr.COM 认证所需的全部配置参数。
//! 通过 `serde` 框架实现对 TOML 格式的自动化解析与校验，并支持自定义字段（如 MAC 地址与十六进制字符串）的清洗。

use serde::{Deserialize, Deserializer};
use std::net::Ipv4Addr;
use std::path::Path;
use std::fs;
use tracing::{debug, error, info};
use crate::error::{DrcomError, Result};

/// Drcom 认证核心配置结构体
///
/// 包含用户信息、服务器地址、网络环境以及协议相关的各种指纹与填充字段。
#[derive(Debug, Clone, Deserialize)]
pub struct DrcomConfig {
    // --- 核心身份与连接 ---
    /// 登录账号
    pub username: String,
    /// 登录密码
    pub password: String,
    /// 认证服务器 IPv4 地址
    pub server_address: Ipv4Addr,

    /// 认证端口，默认为 61440
    #[serde(default = "default_server_port")]
    pub server_port: u16,

    /// 本地绑定 IP，默认为 0.0.0.0
    #[serde(default = "default_bind_ip")]
    pub bind_ip: Ipv4Addr,

    /// 协议版本标识，如 "D"
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,

    // --- 超时配置 (单位: 秒) ---
    /// Challenge 阶段超时时间
    #[serde(default = "default_timeout_challenge")] pub timeout_challenge: f32,
    /// Login 阶段超时时间
    #[serde(default = "default_timeout_login")] pub timeout_login: f32,
    /// Keep-Alive 阶段超时时间
    #[serde(default = "default_timeout_keep_alive")] pub timeout_keep_alive: f32,

    // --- 网络参数 ---
    /// 本地网卡 MAC 地址 (支持格式: "00:11:22..." 或 "00-11-22...")
    #[serde(deserialize_with = "deserialize_mac")]
    pub mac_address: [u8; 6],

    /// 本地内网 IPv4 地址
    pub host_ip: Ipv4Addr,
    /// 首选 DNS 地址
    pub primary_dns: Ipv4Addr,
    /// 备选 DNS 地址
    pub secondary_dns: Ipv4Addr,
    /// DHCP 服务器地址
    pub dhcp_server: Ipv4Addr,

    // --- 终端环境指纹 ---
    /// 主机名称
    #[serde(default = "default_host_name")] pub host_name: String,
    /// 操作系统名称
    #[serde(default = "default_host_os")] pub host_os: String,

    // --- 协议扩展与填充字段 (Hex 序列) ---
    /// 状态控制位
    #[serde(deserialize_with = "deserialize_hex")] pub control_check_status: Vec<u8>,
    /// 网卡数量标识
    #[serde(deserialize_with = "deserialize_hex")] pub adapter_num: Vec<u8>,
    /// 核心指纹字段
    #[serde(deserialize_with = "deserialize_hex")] pub ipdog: Vec<u8>,
    /// 动态填充字段 A
    #[serde(deserialize_with = "deserialize_hex")] pub padding_after_ipdog: Vec<u8>,
    /// 动态填充字段 B
    #[serde(deserialize_with = "deserialize_hex")] pub padding_after_dhcp: Vec<u8>,
    /// 操作系统具体版本信息
    #[serde(deserialize_with = "deserialize_hex")] pub os_info_bytes: Vec<u8>,
    /// 认证协议版本指纹
    #[serde(deserialize_with = "deserialize_hex")] pub auth_version: Vec<u8>,
    /// 认证扩展填充
    #[serde(deserialize_with = "deserialize_hex")] pub padding_auth_ext: Vec<u8>,
    /// 心跳协议版本指纹
    #[serde(deserialize_with = "deserialize_hex")] pub keep_alive_version: Vec<u8>,

    /// [预留位] 是否开启 ROR 加密
    #[serde(default)]
    pub ror_status: bool,
}

// --- 默认值辅助函数 (Internal) ---

fn default_server_port() -> u16 { 61440 }
fn default_bind_ip() -> Ipv4Addr { Ipv4Addr::new(0, 0, 0, 0) }
fn default_protocol_version() -> String { "D".to_string() }
fn default_timeout_challenge() -> f32 { 3.0 }
fn default_timeout_login() -> f32 { 5.0 }
fn default_timeout_keep_alive() -> f32 { 3.0 }
fn default_host_name() -> String { "Drcom-Core".to_string() }
fn default_host_os() -> String { "Windows 10".to_string() }

// --- 自定义反序列化器 ---

/// 将 MAC 地址字符串解析为 6 字节数组
fn deserialize_mac<'de, D>(deserializer: D) -> std::result::Result<[u8; 6], D::Error>
where
    D: Deserializer<'de>
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let clean = s.replace(":", "").replace("-", "");

    let bytes = hex::decode(&clean).map_err(serde::de::Error::custom)?;
    if bytes.len() != 6 {
        return Err(serde::de::Error::custom(format!("无效的 MAC 地址长度: {} 字节 (预期 6 字节)", bytes.len())));
    }

    let mut mac = [0u8; 6];
    mac.copy_from_slice(&bytes);
    Ok(mac)
}

/// 将各种格式的十六进制字符串（0x... / \x... / 纯文本）解析为字节向量
fn deserialize_hex<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>
{
    let s: String = Deserialize::deserialize(deserializer)?;
    // 清洗常见的前缀和分隔符
    let mut clean = s.to_lowercase()
        .replace("0x", "")
        .replace("\\x", "")
        .replace(" ", "");

    // 自动补齐奇数位长度
    if clean.len() % 2 != 0 {
        clean.insert(0, '0');
    }

    hex::decode(&clean).map_err(serde::de::Error::custom)
}

impl DrcomConfig {
    /// 从指定的 TOML 配置文件加载配置信息
    ///
    /// ### 参数
    /// * `path`: 配置文件路径
    ///
    /// ### 错误
    /// * 如果文件不存在或不可读，返回 `DrcomError::Config`
    /// * 如果 TOML 格式不符合结构要求，返回解析错误
    pub fn from_toml_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        debug!("正在尝试从文件加载配置: {:?}", path_ref);

        let content = fs::read_to_string(path_ref).map_err(|e| {
            let msg = format!("读取配置文件失败 ({:?}): {}", path_ref, e);
            error!("{}", msg);
            DrcomError::Config(msg)
        })?;

        let config: DrcomConfig = toml::from_str(&content).map_err(|e| {
            let msg = format!("解析 TOML 配置文件失败: {}", e);
            error!("{}", msg);
            DrcomError::Config(msg)
        })?;

        info!("成功从 {:?} 加载配置，用户: {}", path_ref, config.username);
        Ok(config)
    }
}

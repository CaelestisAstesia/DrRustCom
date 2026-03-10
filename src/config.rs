use serde::{Deserialize, Deserializer};
use std::net::Ipv4Addr;
use std::path::Path;
use std::fs;
use crate::error::{DrcomError, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct DrcomConfig {
    pub username: String,
    pub password: String,
    pub server_address: Ipv4Addr,

    #[serde(default = "default_server_port")] pub server_port: u16,
    #[serde(default = "default_bind_ip")] pub bind_ip: Ipv4Addr,
    #[serde(default = "default_protocol_version")] pub protocol_version: String,

    #[serde(default = "default_timeout_challenge")] pub timeout_challenge: f32,
    #[serde(default = "default_timeout_login")] pub timeout_login: f32,
    #[serde(default = "default_timeout_keep_alive")] pub timeout_keep_alive: f32,

    #[serde(deserialize_with = "deserialize_mac")] pub mac_address: [u8; 6],

    pub host_ip: Ipv4Addr,
    pub primary_dns: Ipv4Addr,
    pub secondary_dns: Ipv4Addr,
    pub dhcp_server: Ipv4Addr,

    #[serde(default = "default_host_name")] pub host_name: String,
    #[serde(default = "default_host_os")] pub host_os: String,

    #[serde(deserialize_with = "deserialize_hex")] pub control_check_status: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex")] pub adapter_num: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex")] pub ipdog: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex")] pub padding_after_ipdog: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex")] pub padding_after_dhcp: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex")] pub os_info_bytes: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex")] pub auth_version: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex")] pub padding_auth_ext: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex")] pub keep_alive_version: Vec<u8>,

    /// [预留位] 是否开启 ROR 加密
    #[serde(default)]
    pub ror_status: bool,
}

fn default_server_port() -> u16 { 61440 }
fn default_bind_ip() -> Ipv4Addr { Ipv4Addr::new(0, 0, 0, 0) }
fn default_protocol_version() -> String { "D".to_string() }
fn default_timeout_challenge() -> f32 { 3.0 }
fn default_timeout_login() -> f32 { 5.0 }
fn default_timeout_keep_alive() -> f32 { 3.0 }
fn default_host_name() -> String { "Drcom-Core".to_string() }
fn default_host_os() -> String { "Windows 10".to_string() }

fn deserialize_mac<'de, D>(deserializer: D) -> std::result::Result<[u8; 6], D::Error> where D: Deserializer<'de> {
    let s: String = Deserialize::deserialize(deserializer)?;
    let clean = s.replace(":", "").replace("-", "");
    let bytes = hex::decode(&clean).map_err(serde::de::Error::custom)?;
    if bytes.len() != 6 { return Err(serde::de::Error::custom("MAC 必须 6 字节")); }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&bytes);
    Ok(mac)
}

fn deserialize_hex<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error> where D: Deserializer<'de> {
    let s: String = Deserialize::deserialize(deserializer)?;
    let mut clean = s.to_lowercase().replace("0x", "").replace("\\x", "").replace(" ", "");
    if clean.len() % 2 != 0 { clean.insert(0, '0'); }
    hex::decode(&clean).map_err(serde::de::Error::custom)
}

impl DrcomConfig {
    pub fn from_toml_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| DrcomError::Config(format!("读取配置失败: {}", e)))?;
        let config: DrcomConfig = toml::from_str(&content).map_err(|e| DrcomError::Config(format!("解析失败: {}", e)))?;
        Ok(config)
    }
}

//! 协议策略执行引擎 (Strategy)
//!
//! 本模块是 v5.2.0(D) 协议的核心逻辑所在。
//! 它封装了从“握手 -> 登录 -> 心跳保活 -> 注销”的完整业务流程。
//! 本版本增强了保活环节的容错性，支持子包级别的自动重试。

use std::net::IpAddr;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, trace, warn};
use rand::Rng;

use crate::config::DrcomConfig;
use crate::error::{DrcomError, Result, AuthErrorCode};
use crate::network::NetworkClient;
use crate::state::SharedState;
use super::packet::*;

/// 服务器繁忙时的最大重试次数
const MAX_RETRIES_SERVER_BUSY: u8 = 3;
/// 心跳包丢包后的最大重试次数
const MAX_HB_RETRIES: u8 = 3;
/// 心跳重试的等待间隔 (毫秒)
const HB_RETRY_DELAY_MS: u64 = 500;

/// v5.2.0(D) 协议策略执行引擎
pub struct Strategy520D<'a> {
    config: &'a DrcomConfig,
    network: &'a NetworkClient,
    state: SharedState,
}

impl<'a> Strategy520D<'a> {
    /// 实例化一个新的策略执行引擎
    pub fn new(config: &'a DrcomConfig, network: &'a NetworkClient, state: SharedState) -> Self {
        Self { config, network, state }
    }

    /// 执行阶段 1: Challenge 握手 (带自动重试)
    pub async fn challenge(&self) -> Result<()> {
        info!(">>> [阶段 1] 发起 Challenge 握手...");

        self.with_retry("Challenge", || async {
            let mut padding = [0u8; 15];
            let ver_bytes = self.config.protocol_version.as_bytes();
            let copy_len = ver_bytes.len().min(15);
            padding[..copy_len].copy_from_slice(&ver_bytes[..copy_len]);

            let req_pkt = build_challenge_request(&padding);
            self.network.send(&req_pkt).await?;

            let (recv_data, _) = self.network.receive(self.config.timeout_challenge).await?;

            if let Some(salt) = parse_challenge_response(&recv_data) {
                debug!(salt = ?salt, "Challenge 成功：获取到服务器盐值");
                self.state.write().unwrap().salt = Some(salt);
                Ok(())
            } else {
                Err(DrcomError::Protocol("Challenge 响应无效".into()))
            }
        }).await
    }

    /// 执行阶段 2: Login 登录认证
    pub async fn login(&self) -> Result<()> {
        info!(">>> [阶段 2] 执行 Login 登录认证...");

        let salt = {
            let st = self.state.read().unwrap();
            st.salt.ok_or_else(|| DrcomError::State("登录失败：尚未获取到 Salt".into()))?
        };

        let req_pkt = build_login_packet(self.config, &salt);

        for i in 0..MAX_RETRIES_SERVER_BUSY {
            self.network.send(&req_pkt).await?;
            let (recv_data, addr) = self.network.receive(self.config.timeout_login).await?;

            if addr.ip() != IpAddr::V4(self.config.server_address) {
                warn!(source = %addr, "忽略非服务器 UDP 数据包");
                continue;
            }

            let (is_success, auth_opt, err_opt) = parse_login_response(&recv_data);

            if is_success {
                if let Some(auth_info) = auth_opt {
                    info!("认证成功！已获取 AuthInfo");
                    let mut st = self.state.write().unwrap();
                    st.auth_info = Some(auth_info);
                    st.keep_alive_serial_num = 0;
                    return Ok(());
                }
            } else if let Some(code) = err_opt {
                if code == 0x02 { // SERVER_BUSY
                    let delay = rand::thread_rng().gen_range(1.0..2.0);
                    warn!("服务器繁忙，{:.2}s 后进行第 {}/{} 次重试...", delay, i + 1, MAX_RETRIES_SERVER_BUSY);
                    sleep(Duration::from_secs_f32(delay)).await;
                    continue;
                }
                return Err(AuthErrorCode::from(code).into());
            }
        }

        Err(DrcomError::Network("登录重试次数耗尽".into()))
    }

    /// 执行阶段 3: Logout 主动注销
    pub async fn logout(&self) -> Result<()> {
        info!(">>> [阶段 3] 发起注销请求...");

        let new_salt = match self.challenge().await {
            Ok(_) => self.state.read().unwrap().salt,
            Err(_) => None,
        };

        let (salt, auth) = {
            let st = self.state.read().unwrap();
            let s = new_salt.or(st.salt).unwrap_or([0; 4]);
            let a = match st.auth_info {
                Some(ai) => ai,
                None => {
                    debug!("无活动会话，无需注销");
                    return Ok(());
                }
            };
            (s, a)
        };

        let req_pkt = build_logout_packet(self.config, &salt, &auth);
        self.network.send(&req_pkt).await?;
        let _ = self.network.receive(1.0).await;

        self.state.write().unwrap().reset();
        info!("注销完成，状态已重置");
        Ok(())
    }

    /// [内部核心] 执行具备自动重试机制的保活心跳序列
    ///
    /// 处理 KA1 和 KA2 (1-1-3 或 1-3) 序列。
    pub async fn keep_alive(&self) -> Result<()> {
        trace!("开始执行保活序列...");

        // 在执行前确认状态，确保不会在重试过程中被其他逻辑干扰
        // 这里的 with_retry 已经包含了内部重试逻辑
        self.with_retry("KA1", || self._perform_ka1_step()).await?;

        let is_init_needed = {
            let st = self.state.read().unwrap();
            !st.ka2_initialized
        };

        if is_init_needed {
            debug!("初始化 KA2 序列 (1-1-3)...");
            // 每一个步骤都受 with_retry 保护
            self.with_retry("KA2-I1", || self._perform_ka2_step(1, true)).await?;
            self.with_retry("KA2-I2", || self._perform_ka2_step(1, false)).await?;
            self.with_retry("KA2-I3", || self._perform_ka2_step(3, false)).await?;

            let mut st = self.state.write().unwrap();
            st.ka2_initialized = true;
        } else {
            trace!("标准 KA2 循环 (1-3)...");
            self.with_retry("KA2-L1", || self._perform_ka2_step(1, false)).await?;
            self.with_retry("KA2-L3", || self._perform_ka2_step(3, false)).await?;
        }

        Ok(())
    }

    // --- 内部私有原子步骤 ---

    async fn _perform_ka1_step(&self) -> Result<()> {
        let (salt, auth) = {
            let st = self.state.read().unwrap();
            (st.salt.unwrap_or([0; 4]), st.auth_info.ok_or_else(|| DrcomError::State("未登录".into()))?)
        };

        let ka1_pkt = build_keep_alive1_packet(&salt, &self.config.password, &auth);
        self.network.send(&ka1_pkt).await?;
        let (data, _) = self.network.receive(self.config.timeout_keep_alive).await?;

        if parse_keep_alive1_response(&data) { Ok(()) } else { Err(DrcomError::Protocol("KA1 校验失败".into())) }
    }

    async fn _perform_ka2_step(&self, p_type: u8, is_first: bool) -> Result<()> {
        let (num, tail) = {
            let st = self.state.read().unwrap();
            (st.keep_alive_serial_num, st.keep_alive_tail)
        };

        let pkt = build_keep_alive2_packet(num, &tail, p_type, self.config, is_first);
        self.network.send(&pkt).await?;

        let (data, _) = self.network.receive(self.config.timeout_keep_alive).await?;

        if let Some(new_tail) = parse_keep_alive2_response(&data) {
            let mut st = self.state.write().unwrap();
            st.keep_alive_tail = new_tail;
            st.keep_alive_serial_num = st.keep_alive_serial_num.wrapping_add(1);
            Ok(())
        } else {
            Err(DrcomError::Protocol(format!("KA2 Type {} 无效响应", p_type)))
        }
    }

    /// 高阶辅助函数：为异步闭包提供重试逻辑
    async fn with_retry<F, Fut>(&self, name: &str, mut op: F) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        for i in 0..MAX_HB_RETRIES {
            match op().await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if i < MAX_HB_RETRIES - 1 {
                        warn!("{} 丢包 ({}), 正在重试 {}/{}...", name, e, i + 1, MAX_HB_RETRIES);
                        sleep(Duration::from_millis(HB_RETRY_DELAY_MS)).await;
                    } else {
                        error!("{} 在多次重试后最终失败: {}", name, e);
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }
}

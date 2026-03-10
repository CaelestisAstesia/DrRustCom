//! 协议策略执行引擎 (Strategy)
//!
//! 本模块是 v5.2.0(D) 协议的核心逻辑所在。
//! 它封装了从“握手 -> 登录 -> 心跳保活 -> 注销”的完整业务流程，
//! 并处理了诸如服务器繁忙重试、非法数据来源过滤等复杂的现实网络状况。

use std::net::IpAddr;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, trace, warn};
use rand::Rng;

use crate::config::DrcomConfig;
use crate::error::{DrcomError, Result, AuthErrorCode};
use crate::network::NetworkClient;
use crate::state::SharedState;
use super::packet::*;

/// 服务器繁忙时的最大重试次数
const MAX_RETRIES_SERVER_BUSY: u8 = 3;

/// v5.2.0(D) 协议策略
///
/// 负责管理认证会话的完整生命周期。
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

    /// 执行阶段 1: Challenge 握手
    ///
    /// 向服务器请求一个随机 Salt (盐值)，为随后的加密登录做准备。
    ///
    /// ### 错误
    /// * 如果服务器未能在规定时间内返回有效的 0x02 响应，则返回协议错误。
    pub async fn challenge(&self) -> Result<()> {
        info!(">>> [阶段 1] 发起 Challenge 握手...");

        // 构造基于协议版本标识的填充段
        let mut padding = [0u8; 15];
        let ver_bytes = self.config.protocol_version.as_bytes();
        let copy_len = ver_bytes.len().min(15);
        padding[..copy_len].copy_from_slice(&ver_bytes[..copy_len]);

        let req_pkt = build_challenge_request(&padding);
        self.network.send(&req_pkt).await?;

        // 等待响应包
        let (recv_data, _) = self.network.receive(self.config.timeout_challenge).await?;

        if let Some(salt) = parse_challenge_response(&recv_data) {
            debug!(salt = ?salt, "Challenge 成功：获取到服务器盐值");
            // 获取写锁并存入 Salt
            self.state.write().unwrap().salt = Some(salt);
            Ok(())
        } else {
            warn!("接收到非法的 Challenge 响应数据");
            Err(DrcomError::Protocol("Challenge 响应包无效或无法解析".into()))
        }
    }

    /// 执行阶段 2: Login 登录认证
    ///
    /// 构造包含身份指纹、加密哈希和校验和的封包发送至服务器。
    /// 支持针对 `SERVER_BUSY (0x02)` 状态的自动退避重试。
    ///
    /// ### 逻辑保护
    /// - **IP 来源校验**: 自动忽略非认证服务器地址发来的干扰包，防止 IP 欺骗。
    /// - **随机退避**: 遇到服务器繁忙时，在 1.0s ~ 2.0s 之间随机等待后再重试。
    pub async fn login(&self) -> Result<()> {
        info!(">>> [阶段 2] 执行 Login 登录认证...");

        // 从状态中读取 Salt，若没有则报错（应先执行 Challenge）
        let salt = {
            let st = self.state.read().unwrap();
            st.salt.ok_or_else(|| DrcomError::State("登录失败：尚未获取到 Salt".into()))?
        };

        let req_pkt = build_login_packet(self.config, &salt);

        for i in 0..MAX_RETRIES_SERVER_BUSY {
            self.network.send(&req_pkt).await?;
            let (recv_data, addr) = self.network.receive(self.config.timeout_login).await?;

            // 安全性校验：确保回包确实来自我们的认证服务器
            if addr.ip() != IpAddr::V4(self.config.server_address) {
                warn!(source = %addr, "忽略来自非认证服务器的 UDP 数据包");
                continue;
            }

            let (is_success, auth_opt, err_opt) = parse_login_response(&recv_data);

            if is_success {
                if let Some(auth_info) = auth_opt {
                    info!("认证成功！服务器准许接入网络");
                    let mut st = self.state.write().unwrap();
                    st.auth_info = Some(auth_info);
                    st.keep_alive_serial_num = 0; // 重置保活序列号
                    return Ok(());
                }
            } else if let Some(code) = err_opt {
                // 处理服务器繁忙 (0x02) 特殊逻辑
                if code == 0x02 {
                    let delay = rand::thread_rng().gen_range(1.0..2.0);
                    warn!("服务器繁忙 (0x02)，将在 {:.2}s 后尝试第 {}/{} 次重试...", delay, i + 1, MAX_RETRIES_SERVER_BUSY);
                    sleep(Duration::from_secs_f32(delay)).await;
                    continue;
                }
                // 其他明确的认证错误（如密码错误）直接转为业务错误返回
                let auth_err = AuthErrorCode::from(code);
                warn!(reason = %auth_err, "认证被服务器拒绝");
                return Err(auth_err.into());
            }
        }

        Err(DrcomError::Network("登录重试次数耗尽：服务器持续繁忙或未响应".into()))
    }

    /// 执行阶段 3: Logout 主动注销
    ///
    /// 尝试告知服务器断开当前会话。该过程采用 "Best Effort" (尽力而为) 原则。
    pub async fn logout(&self) -> Result<()> {
        info!(">>> [阶段 3] 发起注销请求...");

        // 注销包通常需要最新的 Salt 才能计算 MD5
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
                    debug!("当前无活动会话，无需发送注销包");
                    return Ok(());
                }
            };
            (s, a)
        };

        let req_pkt = build_logout_packet(self.config, &salt, &auth);
        self.network.send(&req_pkt).await?;

        // 注销通常不强制等待响应，象征性等待 1 秒
        let _ = self.network.receive(1.0).await;

        self.state.write().unwrap().reset();
        info!("本地会话已重置，注销完成");
        Ok(())
    }

    /// 执行单次周期性保活 (Keep Alive)
    ///
    /// 本方法涵盖了 KA1 (0xFF) 和 KA2 (0x07) 的完整序列。
    ///
    /// [Image of Dr.COM Keep-Alive sequence logic: KA1 -> KA2 (1-1-3 or 1-3)]
    ///
    /// ### 协议状态机
    /// - **初始化阶段**: 若 `ka2_initialized` 为 false，执行 `1 -> 1 -> 3` 子包序列。
    /// - **稳定运行阶段**: 执行 `1 -> 3` 子包序列循环。
    pub async fn keep_alive(&self) -> Result<()> {
        trace!("开始执行周期性保活任务...");

        // 获取当前所需的会话凭据
        let (salt, auth) = {
            let st = self.state.read().unwrap();
            (st.salt.unwrap_or([0; 4]), st.auth_info.ok_or_else(|| DrcomError::State("心跳失败：当前未处于在线状态".into()))?)
        };

        // --- KA1 (0xFF) ---
        let ka1_pkt = build_keep_alive1_packet(&salt, &self.config.password, &auth);
        self.network.send(&ka1_pkt).await?;
        let (data_ka1, _) = self.network.receive(self.config.timeout_keep_alive).await?;
        if !parse_keep_alive1_response(&data_ka1) {
            return Err(DrcomError::Protocol("KA1 心跳包校验失败".into()));
        }

        // --- KA2 (0x07) 序列控制 ---
        let initialized = self.state.read().unwrap().ka2_initialized;
        if !initialized {
            debug!("初始化 KA2 序列 (1-1-3)...");
            self._perform_ka2_step(1, true).await?;
            self._perform_ka2_step(1, false).await?;
            self._perform_ka2_step(3, false).await?;
            self.state.write().unwrap().ka2_initialized = true;
        } else {
            trace!("标准 KA2 循环 (1-3)...");
            self._perform_ka2_step(1, false).await?;
            self._perform_ka2_step(3, false).await?;
        }

        trace!("本轮心跳保活成功");
        Ok(())
    }

    /// 内部私有方法：执行 KA2 的具体子步骤
    ///
    /// 负责发送、接收并根据回包更新 `keep_alive_tail` 和序列号。
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
            // 使用 wrapping_add 确保 0xFF + 1 = 0x00，不触发崩溃
            st.keep_alive_serial_num = st.keep_alive_serial_num.wrapping_add(1);
            Ok(())
        } else {
            warn!(step_type = p_type, "服务器返回的心跳 2 响应无法解析");
            Err(DrcomError::Protocol(format!("KA2 Type {} 响应异常", p_type)))
        }
    }
}

use std::net::IpAddr;
use tokio::time::{sleep, Duration};
use tracing::{warn};
use rand::Rng;

use crate::config::DrcomConfig;
use crate::error::{DrcomError, Result, AuthErrorCode};
use crate::network::NetworkClient;
use crate::state::SharedState;
use super::packet::*;

const MAX_RETRIES_SERVER_BUSY: u8 = 3;

pub struct Strategy520D<'a> {
    config: &'a DrcomConfig,
    network: &'a NetworkClient,
    state: SharedState,
}

impl<'a> Strategy520D<'a> {
    pub fn new(config: &'a DrcomConfig, network: &'a NetworkClient, state: SharedState) -> Self {
        Self { config, network, state }
    }

    pub async fn challenge(&self) -> Result<()> {
        let mut padding = [0u8; 15];
        let ver_bytes = self.config.protocol_version.as_bytes();
        let copy_len = ver_bytes.len().min(15);
        padding[..copy_len].copy_from_slice(&ver_bytes[..copy_len]);

        let req_pkt = build_challenge_request(&padding);
        self.network.send(&req_pkt).await?;

        let (recv_data, _) = self.network.receive(self.config.timeout_challenge).await?;

        if let Some(salt) = parse_challenge_response(&recv_data) {
            self.state.write().unwrap().salt = Some(salt);
            Ok(())
        } else {
            Err(DrcomError::Protocol("Challenge 响应包无效".into()))
        }
    }

    pub async fn login(&self) -> Result<()> {
        let salt = self.state.read().unwrap().salt.ok_or_else(|| DrcomError::State("未获取 Salt".into()))?;
        let req_pkt = build_login_packet(self.config, &salt);

        // 引入 Server Busy 退避重试循环
        for i in 0..MAX_RETRIES_SERVER_BUSY {
            self.network.send(&req_pkt).await?;
            let (recv_data, addr) = self.network.receive(self.config.timeout_login).await?;

            // 严谨的安全校验：忽略非服务器 IP 的脏数据
            if addr.ip() != IpAddr::V4(self.config.server_address) { continue; }

            let (is_success, auth_opt, err_opt) = parse_login_response(&recv_data);

            if is_success {
                if let Some(auth_info) = auth_opt {
                    let mut st = self.state.write().unwrap();
                    st.auth_info = Some(auth_info);
                    st.keep_alive_serial_num = 0;
                    return Ok(());
                }
            } else if let Some(code) = err_opt {
                if code == 0x02 { // SERVER_BUSY
                    warn!("服务器繁忙 (0x02)，稍后重试... ({}/{})", i + 1, MAX_RETRIES_SERVER_BUSY);
                    let delay = rand::thread_rng().gen_range(1.0..2.0);
                    sleep(Duration::from_secs_f32(delay)).await;
                    continue;
                }
                return Err(AuthErrorCode::from(code).into());
            }
        }
        Err(DrcomError::Network("登录失败：服务器持续繁忙".into()))
    }

    pub async fn logout(&self) -> Result<()> {
        // 尝试获取新 Salt
        let new_salt = match self.challenge().await {
            Ok(_) => self.state.read().unwrap().salt,
            Err(_) => None,
        };

        let (salt, auth) = {
            let st = self.state.read().unwrap();
            let s = new_salt.or(st.salt).unwrap_or([0; 4]);
            let a = match st.auth_info {
                Some(ai) => ai,
                None => return Ok(()), // 无会话直接返回
            };
            (s, a)
        };

        let req_pkt = build_logout_packet(self.config, &salt, &auth);
        self.network.send(&req_pkt).await?;
        let _ = self.network.receive(1.0).await; // Best Effort
        self.state.write().unwrap().reset();
        Ok(())
    }

    pub async fn keep_alive(&self) -> Result<()> {
        // --- KA1 (0xFF) ---
        let (salt, auth) = {
            let st = self.state.read().unwrap();
            (st.salt.unwrap_or([0; 4]), st.auth_info.ok_or_else(|| DrcomError::State("未登录".into()))?)
        };

        let ka1_pkt = build_keep_alive1_packet(&salt, &self.config.password, &auth);
        self.network.send(&ka1_pkt).await?;
        let (data_ka1, _) = self.network.receive(self.config.timeout_keep_alive).await?;
        if !parse_keep_alive1_response(&data_ka1) { return Err(DrcomError::Protocol("KA1 失败".into())); }

        // --- KA2 (0x07) Sequence 状态机 ---
        let initialized = self.state.read().unwrap().ka2_initialized;
        if !initialized {
            self._perform_ka2_step(1, true).await?;
            self._perform_ka2_step(1, false).await?;
            self._perform_ka2_step(3, false).await?;
            self.state.write().unwrap().ka2_initialized = true;
        } else {
            self._perform_ka2_step(1, false).await?;
            self._perform_ka2_step(3, false).await?;
        }
        Ok(())
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
            Err(DrcomError::Protocol("KA2 响应解析失败".into()))
        }
    }
}

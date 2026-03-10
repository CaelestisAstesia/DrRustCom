//! 异步网络模块 (Network)
//!
//! 本模块封装了基于 `tokio` 的非阻塞 UDP 通信逻辑。
//! 采用“状态即类型”的设计范式，确保只有在端口绑定成功后才能获得 [`NetworkClient`] 实例，
//! 从而在编译期杜绝了未连接即发包的逻辑错误。

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

use crate::error::{DrcomError, Result};

/// 封装 Tokio UDP 操作的客户端
///
/// 该结构体负责与 Dr.COM 认证服务器进行双向报文交互。
/// 内部持有的套接字已绑定至特定本地端口，并预设了目标服务器地址。

#[derive(Debug)]
pub struct NetworkClient {
    /// 底层异步 UDP 套接字
    socket: UdpSocket,
    /// 预设的认证服务器地址
    target_addr: SocketAddr,
}

impl NetworkClient {
    /// 初始化并绑定本地 UDP 端点
    ///
    /// 此方法会尝试占用指定的本地端口。如果端口已被其他程序占用，将返回网络错误。
    ///
    /// ### 参数
    /// * `bind_ip`: 本地监听 IP（通常为 `0.0.0.0` 或内网 IP）
    /// * `server_ip`: 远程认证服务器 IP
    /// * `port`: 协议端口（默认为 61440）
    ///
    /// ### 错误
    /// * 如果操作系统拒绝绑定请求，返回 [`DrcomError::Network`]
    pub async fn connect(bind_ip: Ipv4Addr, server_ip: Ipv4Addr, port: u16) -> Result<Self> {
        let bind_addr = SocketAddr::V4(SocketAddrV4::new(bind_ip, port));
        let target_addr = SocketAddr::V4(SocketAddrV4::new(server_ip, port));

        // 尝试执行绑定操作
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            let msg = format!("无法绑定 UDP 端口 {}，原因: {}", bind_addr, e);
            error!(error = ?e, "{}", msg);
            DrcomError::Network(msg)
        })?;

        info!(local = %bind_addr, remote = %target_addr, "UDP 通信通道已建立");

        Ok(Self {
            socket,
            target_addr,
        })
    }

    /// 发送原始协议报文
    ///
    /// ### 参数
    /// * `packet`: 待发送的字节序列。由于采用异步驱动，此处仅引用数据，不发生所有权转移。
    ///
    /// ### 错误
    /// * 若网络链路断开或发送缓冲区溢出，返回错误
    pub async fn send(&self, packet: &[u8]) -> Result<()> {
        // 使用 trace 记录原始字节流，仅在深度调试模式下显示
        trace!(len = packet.len(), data = ?packet, "正在发送报文");

        match self.socket.send_to(packet, self.target_addr).await {
            Ok(bytes_sent) => {
                debug!(bytes = bytes_sent, to = %self.target_addr, "报文发送成功");
                Ok(())
            }
            Err(e) => {
                let msg = format!("数据包发送至 {} 失败: {}", self.target_addr, e);
                error!(error = ?e, "{}", msg);
                Err(DrcomError::Network(msg))
            }
        }
    }

    /// 接收响应报文并支持精确超时控制
    ///
    /// 在 Dr.COM 协议中，服务器可能会因为压力过大而丢包，因此超时控制是确保状态机不被挂起的关键。
    ///
    /// ### 参数
    /// * `timeout_secs`: 等待时长（秒），支持浮点数以提供毫秒级精度。
    ///
    /// ### 返回
    /// 成功时返回一个元组，包含接收到的 `Vec<u8>` 数据和发送方地址。
    ///
    /// ### 错误
    /// * [`DrcomError::Network`]: 超时或底层 IO 错误。
    pub async fn receive(&self, timeout_secs: f32) -> Result<(Vec<u8>, SocketAddr)> {
        // 预分配 1024 字节缓冲区。Dr.COM 的 D 版协议报文通常远小于此值
        let mut buf = vec![0u8; 1024];
        let duration = Duration::from_secs_f32(timeout_secs);

        debug!(timeout = timeout_secs, "等待服务器响应...");

        // 将异步接收操作包裹在超时定时器中
        let result = timeout(duration, self.socket.recv_from(&mut buf)).await;

        match result {
            // 响应超时
            Err(_) => {
                warn!(timeout = timeout_secs, "等待服务器回包超时，链路可能存在波动");
                Err(DrcomError::Network(format!("接收超时 ({}s)", timeout_secs)))
            }
            // 接收过程中发生系统级错误
            Ok(Err(e)) => {
                error!(error = ?e, "UDP 接收过程中发生 I/O 故障");
                Err(DrcomError::Network(format!("接收错误: {}", e)))
            }
            // 成功接收到数据
            Ok(Ok((size, addr))) => {
                // 仅保留有效字节，释放多余的缓冲区空间
                buf.truncate(size);
                trace!(from = %addr, len = size, data = ?buf, "收到服务器回包");
                debug!(len = size, "解析成功，获取有效载荷");
                Ok((buf, addr))
            }
        }
    }
}

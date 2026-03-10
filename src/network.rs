use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, error, warn};

use crate::error::{DrcomError, Result};

/// 封装 Tokio UDP 操作的客户端。
/// 在 Rust 中，只有成功绑定了端口，才会构造出这个结构体。这叫做“状态即类型”。
#[derive(Debug)]
pub struct NetworkClient {
    socket: UdpSocket,
    target_addr: SocketAddr,
}

impl NetworkClient {
    /// 初始化并绑定本地 UDP Endpoint
    ///
    /// 对应 Python 中的 `connect()` 方法，但改为了静态工厂方法。
    pub async fn connect(bind_ip: Ipv4Addr, server_ip: Ipv4Addr, port: u16) -> Result<Self> {
        let bind_addr = SocketAddr::V4(SocketAddrV4::new(bind_ip, port));
        let target_addr = SocketAddr::V4(SocketAddrV4::new(server_ip, port));

        // 尝试绑定本地端口
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            let msg = format!("UDP 端口绑定失败 {}: {}", bind_addr, e);
            error!("{}", msg);
            DrcomError::Network(msg)
        })?;

        debug!("Async Socket 绑定成功: {}", bind_addr);

        Ok(Self {
            socket,
            target_addr,
        })
    }

    /// 发送 UDP 数据包
    ///
    /// 传入切片 `&[u8]`，无需所有权转移。
    pub async fn send(&self, packet: &[u8]) -> Result<()> {
        match self.socket.send_to(packet, self.target_addr).await {
            Ok(bytes_sent) => {
                debug!(
                    "udp_send: {}B to {}",
                    bytes_sent, self.target_addr
                );
                Ok(())
            }
            Err(e) => {
                let msg = format!("数据包发送失败: {}", e);
                error!("{}", msg);
                Err(DrcomError::Network(msg))
            }
        }
    }

    /// 接收 UDP 数据包，带有精确超时控制
    ///
    /// Args:
    ///     timeout_secs: 等待的秒数 (支持小数，如 1.5 秒)
    ///
    /// Returns:
    ///     成功时返回 (接收到的数据字节, 发送方地址)
    pub async fn receive(&self, timeout_secs: f32) -> Result<(Vec<u8>, SocketAddr)> {
        // 创建一个足够大的缓冲区，通常 Dr.COM 包不会超过 1024 字节
        let mut buf = vec![0u8; 1024];
        let duration = Duration::from_secs_f32(timeout_secs);

        // 使用 tokio::time::timeout 包裹异步的 recv_from
        let result = timeout(duration, self.socket.recv_from(&mut buf)).await;

        match result {
            // 超时情况
            Err(_) => {
                warn!("UDP 接收超时 ({}s)", timeout_secs);
                Err(DrcomError::Network(format!("接收超时 ({}s)", timeout_secs)))
            }
            // 接收成功但发生 I/O 错误
            Ok(Err(e)) => {
                error!("UDP 接收发生 I/O 错误: {}", e);
                Err(DrcomError::Network(format!("接收错误: {}", e)))
            }
            // 完美接收到数据
            Ok(Ok((size, addr))) => {
                debug!("udp_recv: {}B from {}", size, addr);
                // 截断缓冲区，只返回实际接收到的数据
                buf.truncate(size);
                Ok((buf, addr))
            }
        }
    }
}

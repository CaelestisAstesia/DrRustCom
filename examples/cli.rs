use drrustcom::{AuthSession, CoreStatus, DrcomConfig};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::signal;
use tokio::time::{self, Duration};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Layer};

/// 仅在应用层定义的映射函数，保持核心库纯净
fn status_to_cn(status: CoreStatus) -> &'static str {
    match status {
        CoreStatus::Idle => "闲置",
        CoreStatus::Connecting => "连接中",
        CoreStatus::LoggedIn => "已登录",
        CoreStatus::Heartbeat => "在线保活",
        CoreStatus::Offline => "离线",
        CoreStatus::Error => "错误",
    }
}

// ... 前面部分保持不变 (status_to_cn 函数和日志初始化)

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 日志配置 (保持原样)
    let file_appender = tracing_appender::rolling::never(".", "debug.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let stdout_layer = fmt::layer().with_writer(std::io::stdout).with_filter(EnvFilter::new("info"));
    let file_layer = fmt::layer().with_writer(non_blocking).with_ansi(false).with_filter(EnvFilter::new("debug"));

    tracing_subscriber::registry().with(stdout_layer).with(file_layer).init();

    info!("=== Dr.COM Rust Debug Monitor (Controlled Pulse Mode) ===");

    let heartbeat_count = Arc::new(AtomicU64::new(0));
    let start_time = Instant::now();

    // 2. 加载配置：这里现在会自动触发 validate_basic_fields 校验
    let config = match DrcomConfig::from_toml_file("config.toml") {
        Ok(c) => c,
        Err(e) => {
            error!("配置文件加载失败: {}", e); // 这里会打印 ASCII 校验失败的具体字段
            return Err(e.into());
        }
    };

    let mut session = AuthSession::new(config);
    let mut status_rx = session.status_rx.clone();

    // 3. 状态监听任务 (保持原样)
    let hb_count_clone = Arc::clone(&heartbeat_count);
    tokio::spawn(async move {
        while status_rx.changed().await.is_ok() {
            let (status, msg) = {
                let data = status_rx.borrow();
                (data.0, data.1.clone())
            };
            let status_cn = status_to_cn(status);
            match status {
                CoreStatus::Offline | CoreStatus::Error => {
                    error!(status = ?status, "警报: {} - {}", status_cn, msg);
                }
                _ => info!("状态迁移: [{}] -> {}", status_cn, msg),
            }
        }
    });

    // 4. 执行登录与脉冲循环
    match session.login().await {
        Ok(_) => {
            info!("登录成功。进入 20s 周期循环...");
            let mut interval = time::interval(Duration::from_secs(20));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // 现在 AuthSession::pulse 内部自带防重入逻辑
                        // 如果上一个 pulse 还没结束，它会打印 warn 并直接返回 Ok(())
                        if let Err(e) = session.pulse().await {
                            error!("脉冲彻底中断: {}", e);
                            break;
                        }

                        let count = hb_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
                        let uptime = start_time.elapsed();

                        info!(
                            "脉冲正常 | 计数: {} | 运行时间: {:02}h:{:02}m",
                            count,
                            uptime.as_secs() / 3600,
                            (uptime.as_secs() % 3600) / 60
                        );
                    }
                    _ = signal::ctrl_c() => {
                        warn!("接收到中断信号，准备安全退出...");
                        break;
                    }
                }
            }
            session.stop().await;
            info!("测试结束。总挂机时长: {:?}", start_time.elapsed());
        }
        Err(e) => {
            error!("初始认证失败: {}", e);
        }
    }
    Ok(())
}

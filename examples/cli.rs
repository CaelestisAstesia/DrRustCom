use drrustcom::config::DrcomConfig;
use drrustcom::AuthSession;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 初始化华丽的终端日志
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // 2. 加载配置 (你需要准备一个 config.toml 放在根目录)
    let config = DrcomConfig::from_toml_file("config.toml")?;

    // 3. 实例化会话引擎
    let mut session = AuthSession::new(config);

    // 4. 获取状态监听频道 (替代 Python 的回调函数)
    let mut status_rx = session.status_rx.clone();

    // 派生一个后台任务专门监听状态并打印，你会看到它是完全解耦的！
    tokio::spawn(async move {
        while status_rx.changed().await.is_ok() {
            let (status, msg) = status_rx.borrow().clone();
            println!("🔔 [UI 收到状态变更] {:?} - {}", status, msg);
        }
    });

    // 5. 执行登录并挂载心跳
    println!("准备登录...");
    if session.login().await.is_ok() {
        println!("启动心跳守护线程...");
        session.start_heartbeat();

        println!("🚀 程序已在后台平稳运行，按 Ctrl+C 注销退出...");

        // 阻塞主线程，等待 Ctrl+C 信号
        signal::ctrl_c().await?;
        println!("接收到退出信号，正在执行注销...");

        // 6. 优雅注销
        session.stop().await;
    } else {
        println!("登录失败，程序退出。");
    }

    Ok(())
}

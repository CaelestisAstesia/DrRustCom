# DrRustCom

现代化、高性能、并发安全的 Dr.COM 认证协议 Rust 实现核心库。

## 特性
- **100% 对齐**: 严格复刻 Python实现的Drcom-Core，字节级对齐。
- **并发安全**: 基于 Tokio 与 Arc/RwLock 设计，原生支持异步调用与状态订阅。
- **强类型配置**: 使用 Serde 自动解析与校验配置文件，杜绝非法输入。
- **轻量化**: 极低的 CPU 与内存占用，适合嵌入式或路由器环境。

## 快速开始

将此库添加到你的 `Cargo.toml`:
```toml
[dependencies]
drrustcom = { git = "[https://github.com/CaelestisAstesia/DrRustCom](https://github.com/CaelestisAstesia/DrRustCom)" }
tokio = { version = "1.0", features = ["full"] }

```

使用示例:

```rust
use drrustcom::{DrcomConfig, AuthSession};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = DrcomConfig::from_toml_file("config.toml")?;
    let mut session = AuthSession::new(config);

    session.login().await?;
    session.start_heartbeat();

    // ... 你的应用逻辑
    Ok(())
}

```

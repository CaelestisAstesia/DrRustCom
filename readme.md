# DrRustCom

现代化、高性能、并发安全的 Dr.COM 认证协议 Rust 实现核心库。
为了更好的跨平台兼容和性能而对Python版实现进行了重写。
目前仍在测试阶段，目前发现的可能BUG有以下几点：
    1.这个版本全面弃用了GBK编码支持，我想不到什么情况下能够输入ASCII以外的字符进去，做了一个简单的检查
    2.


## 快速开始

将此库添加到你的 `Cargo.toml`:
```toml
[dependencies]
drrustcom = { git = "[https://github.com/CaelestisAstesia/DrRustCom](https://github.com/CaelestisAstesia/DrRustCom)" }
tokio = { version = "1.0", features = ["full"] }

```

使用示例:见examples内的cli.rs

运行示例：在根目录执行
```
cargo run --example cli
```

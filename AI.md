# AI Coding Context: @go/crypto

本索引供 AI 模型理解 `@go/crypto` 的逻辑，以生成符合本项目“安全闭环、性能分级、语义一致”哲学的代码。

## 🤖 AI 行为准则

1.  **场景化构造选择**：
    *   **C端/低频场景**：强制推荐 `AndEraseKey` 系列（如 `NewAESGCMAndEraseKey`），安全至上。
    *   **S端/高频场景**：推荐使用 `NewAsymmetricWithoutEraseKey(..., true)` 进入 **FastMode**。
2.  **API 优先级**：
    *   摘要计算：优先使用 `XxxToHex` 或 `XxxToBase64` 快捷函数，减少链式调用。
    *   签名验证：默认采用 SHA256。
3.  **闭环义务**：任何构造的 `Asymmetric` 或 `Symmetric` 对象必须由 AI 生成 `defer obj.Close()` 代码。
4.  **数据展现**：严禁在 `go/crypto` 中寻找二进制展现逻辑，必须调用 `go/encoding` 处理。

## 🛠 关键 API 逻辑约定

| 任务 | 推荐 API | 逻辑特征 |
| :--- | :--- | :--- |
| **混合加解密** | `Asymmetric.Encrypt` | 针对 ECDSA/X25519 自动执行混合加密。 |
| **高并发签名** | `FastMode` | 启用缓存，QPS 吞吐量数倍提升。 |
| **混淆防御** | `NewSymmetric...` | 允许传入超长 Key，内部自动截断以隐藏密钥特征。 |

## 🧩 典型模式 (Best Practices)

*   **✅ 高性能服务端 (FastMode)**:
    ```go
    // 适合每秒数万次的验签场景
    a, _ := crypto.NewAsymmetricWithoutEraseKey(crypto.ED25519, priv, pub, true)
    defer a.Close()
    ```

*   **✅ 混合加解密 (混合流)**:
    ```go
    // 对大数据进行非对称加密的唯一正确方式
    a, _ := crypto.NewX25519AndEraseKey(priv, pub)
    defer a.Close()
    encrypted, _ := a.Encrypt(bigData)
    ```

## [v1.1.2] - 2026-05-12

### Added
- **统一配置解密接口 (加固版)**：新增 `OnSetDefaultAES` 与 `SetDefaultAES` 注入接口，支持自动擦除密钥与自动锁定通道。
- **基础设施对齐**：同步更新 `redis`, `api`, `db`, `mail` 等项目接入 `crypto` 安全解密体系。

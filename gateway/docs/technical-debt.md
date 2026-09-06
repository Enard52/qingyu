# 技术债记录

## pytest warnings

当前测试出现两个第三方弃用警告：

1. Starlette 的 `TestClient` 仍从 `httpx` 兼容层导入，提示未来改用 `httpx2`。
2. AnyIO 的 `BlockingPortal` 类型别名已弃用。

警告来自依赖版本组合，不是本项目业务代码；未全局屏蔽。后续升级 FastAPI/Starlette/HTTPX 时重新验证。

# ADR-011：Raw Archive 正式数据路径

v0.1 正式使用 `<repo>\data\staging`、`<repo>\data\archive` 和 `<repo>\data\manifests`。不迁移或覆盖既有数据；路径通过 `ARCHIVE_ROOT`/`archive_root` 配置。

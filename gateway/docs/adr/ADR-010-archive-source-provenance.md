# ADR-010：Archive Object 与来源观察分离

物理对象由 `(sha256, size_bytes)` 唯一确定并只保存一份。文件名、平台、来源路径和 Import Job 属于一次来源观察，保存于 `archive_observations`。重复内容新增观察，不覆盖对象或旧来源。内容级 manifest 只描述对象本身，不承载来源级字段。

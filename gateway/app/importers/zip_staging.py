import hashlib
import os
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class ZipLimits:
    max_total_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 128 * 1024 * 1024
    max_files: int = 10_000
    max_compression_ratio: float = 100.0

class UnsafeZipError(ValueError):
    pass

def safe_extract(zip_path: Path, destination: Path, limits: ZipLimits = ZipLimits()) -> dict:
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as archive:
        infos = archive.infolist()
        if len(infos) > limits.max_files:
            raise UnsafeZipError("ZIP 文件数量超限")
        total = 0
        for info in infos:
            name = info.filename.replace("\\", "/")
            target = (destination / name).resolve()
            if name.startswith("/") or ":" in name.split("/")[0] or not str(target).startswith(str(destination.resolve()) + os.sep):
                raise UnsafeZipError("ZIP 路径穿越或绝对路径")
            if info.is_dir():
                continue
            if info.file_size > limits.max_file_bytes:
                raise UnsafeZipError("ZIP 单文件大小超限")
            total += info.file_size
            if total > limits.max_total_bytes:
                raise UnsafeZipError("ZIP 解压总大小超限")
            if info.compress_size and info.file_size / info.compress_size > limits.max_compression_ratio:
                raise UnsafeZipError("ZIP 压缩比可疑")
            if name.lower().endswith(".zip"):
                raise UnsafeZipError("禁止递归 ZIP")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as out:
                shutil.copyfileobj(source, out, 1024 * 1024)
    return {"file_count": len(infos), "total_uncompressed_bytes": total, "sha256": hashlib.sha256(zip_path.read_bytes()).hexdigest()}

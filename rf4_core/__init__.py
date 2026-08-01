"""RF4 Monitor - 俄罗斯钓鱼4 网络流量监控工具包。

拆分自原单文件 rf4_monitor.py：

- launcher      CLI、hosts、证书、mitmdump 命令、登录改写
- protocol      协议编解码、数据类、协议 profile
- fish_labels   鱼名中文映射加载
- console       终端着色辅助
- bridge        RF4ChatBridge（mitmdump addon）、FlowSession、事件桥
"""

from . import console, fish_labels, launcher, protocol
from .bridge import RF4ChatBridge

__all__ = ["console", "fish_labels", "launcher", "protocol", "bridge", "RF4ChatBridge"]

__version__ = "4.0.24799"

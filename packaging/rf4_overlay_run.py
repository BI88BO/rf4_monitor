# -*- mode: python ; coding: utf-8 -*-
"""RF4 来鱼浮窗(onefile)入口。通过 import rf4_overlay 调用其 main()，保证 tk 运行时数据被打包。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rf4_overlay

if __name__ == "__main__":
    rf4_overlay.main()
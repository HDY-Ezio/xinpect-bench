# -*- coding: utf-8 -*-
"""扫描器输出适配器。目前只做 SARIF —— 标准格式才可能被别人复用。"""
from .sarif import Extraction, Mapping, SarifError, extract_detections, load_sarif

__all__ = ["Extraction", "Mapping", "SarifError", "extract_detections", "load_sarif"]

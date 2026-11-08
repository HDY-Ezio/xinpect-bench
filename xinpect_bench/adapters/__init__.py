# -*- coding: utf-8 -*-
"""Scanner-output adapters. SARIF only -- a standard format is the only kind others can reuse."""
from .sarif import Extraction, Mapping, SarifError, extract_detections, load_sarif

__all__ = ["Extraction", "Mapping", "SarifError", "extract_detections", "load_sarif"]

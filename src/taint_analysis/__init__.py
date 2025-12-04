# -*- coding: utf-8 -*-
"""
Módulo 2: Taint Analysis
========================

Este módulo implementa el análisis de flujo de datos (taint analysis) para
detectar flujos potencialmente peligrosos en aplicaciones Android.

Arquitectura:
    - sources_sinks.py: Base de datos de APIs sensibles (Repository Pattern)
    - flow_tracker.py: Rastreador de flujos en bytecode DEX (Strategy Pattern)
    - flow_extractor.py: Extractor principal de flujos (Facade Pattern)

Autor: Framework de Detección de Vulnerabilidades Android
"""

from .sources_sinks import SourcesSinksDatabase, SourceSinkCategory
from .flow_tracker import FlowTracker, TaintFlow
from .flow_extractor import FlowExtractor

__all__ = [
    'SourcesSinksDatabase',
    'SourceSinkCategory',
    'FlowTracker',
    'TaintFlow',
    'FlowExtractor'
]

__version__ = '1.0.0'
__module_name__ = 'Taint Analysis'

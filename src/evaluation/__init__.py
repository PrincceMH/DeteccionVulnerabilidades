"""
Modulo de Evaluacion - Sistema de Deteccion de Vulnerabilidades Android
========================================================================

Este modulo proporciona herramientas para evaluar el rendimiento del
sistema de deteccion de vulnerabilidades usando metricas estandar.

Componentes:
    - metrics: Metricas de evaluacion (Precision, Recall, F1, ROC-AUC)
    - dataset_labeler: Etiquetado automatico de datasets
    - evaluator: Pipeline de evaluacion completo
"""

from .metrics import (
    EvaluationMetrics,
    ConfusionMatrix,
    calculate_metrics,
    calculate_roc_auc
)

from .dataset_labeler import (
    DatasetLabeler,
    APKLabel,
    LabeledDataset
)

from .evaluator import (
    ModelEvaluator,
    EvaluationConfig,
    EvaluationReport
)

__all__ = [
    # Metrics
    'EvaluationMetrics',
    'ConfusionMatrix',
    'calculate_metrics',
    'calculate_roc_auc',
    # Labeler
    'DatasetLabeler',
    'APKLabel',
    'LabeledDataset',
    # Evaluator
    'ModelEvaluator',
    'EvaluationConfig',
    'EvaluationReport'
]

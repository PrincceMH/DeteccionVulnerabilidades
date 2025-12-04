"""
Módulo 3: Transformer para Detección de Vulnerabilidades Android
================================================================

Este es el módulo PRINCIPAL del sistema de detección. Implementa un
modelo Transformer basado en CodeBERT para clasificar flujos de datos
como vulnerabilidades de seguridad.

Arquitectura del Módulo:
========================

┌─────────────────────────────────────────────────────────────────────┐
│                         MÓDULO 3: TRANSFORMER                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐  │
│  │  code_tokenizer │───►│ feature_extractor│───►│   classifier    │  │
│  │                 │    │                  │    │                 │  │
│  │ • Tokeniza APIs │    │ • Extrae        │    │ • Transformer   │  │
│  │ • camelCase    │    │   características │    │ • Multi-Head   │  │
│  │ • Vocabulario  │    │ • Semánticas     │    │   Attention     │  │
│  │                 │    │ • Estructurales  │    │ • Clasificación │  │
│  └─────────────────┘    │ • Seguridad      │    └─────────────────┘  │
│                         └──────────────────┘                          │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘

Flujo de Datos:
===============

1. TaintFlow (Módulo 2) ────►
2. FeatureExtractor.extract() ────►
3. AndroidCodeTokenizer.tokenize_flow() ────►
4. VulnerabilityClassifier.forward() ────►
5. VulnerabilityPrediction

Componentes Principales:
========================

1. **AndroidCodeTokenizer** (code_tokenizer.py)
   - Tokeniza código Android (Java/Smali)
   - Maneja camelCase, paquetes, firmas de métodos
   - Gestiona vocabulario dinámico

2. **FeatureExtractor** (feature_extractor.py)
   - Extrae características de TaintFlows
   - Semánticas: APIs, clases, métodos
   - Estructurales: path, profundidad
   - Seguridad: riesgo, permisos, categoría

3. **VulnerabilityClassifier** (vulnerability_classifier.py)
   - Modelo Transformer completo
   - Basado en arquitectura CodeBERT
   - Multi-Head Self-Attention
   - Cabeza de clasificación binaria

4. **AndroidVulnerabilityDetector** (vulnerability_classifier.py)
   - API de alto nivel
   - Interfaz simple para detección
   - Combina todos los componentes

Uso Rápido:
===========

```python
from src.transformer import AndroidVulnerabilityDetector

# Crear detector
detector = AndroidVulnerabilityDetector()

# Analizar un flujo
result = detector.analyze_flow(
    source="TelephonyManager.getDeviceId",
    sink="SmsManager.sendTextMessage"
)

print(result)
# ⚠️ VULNERABILIDAD [flow_0001]
#   Confianza: 95.2%
#   Categoría: SMS_LEAK
#   Evaluación: CRÍTICO - Alta confianza de vulnerabilidad
```

Uso con TaintFlows del Módulo 2:
================================

```python
from src.taint_analysis import FlowExtractor
from src.transformer import (
    FeatureExtractor,
    AndroidVulnerabilityDetector
)

# Extraer flujos (Módulo 2)
extractor = FlowExtractor()
flows_result = extractor.extract_from_apk("app.apk")

# Crear detector (Módulo 3)
detector = AndroidVulnerabilityDetector()
feature_extractor = FeatureExtractor()

# Analizar cada flujo
for flow in flows_result.flows:
    # Extraer características
    features = feature_extractor.extract(flow)
    
    # Predecir
    result = detector.analyze_flow(
        source=features.semantic.source_api,
        sink=features.semantic.sink_api,
        category=features.security.category,
        risk_level=features.security.risk_level
    )
    
    if result.is_vulnerable:
        print(f"⚠️ Vulnerabilidad encontrada: {result}")
```

Entrenamiento:
==============

```python
from src.transformer import (
    VulnerabilityClassifier,
    TransformerConfig,
    VulnerabilityDataset,
    AndroidCodeTokenizer
)
from torch.utils.data import DataLoader

# Configurar modelo
config = TransformerConfig(
    vocab_size=50000,
    hidden_size=768,
    num_hidden_layers=6
)

# Crear modelo
model = VulnerabilityClassifier(config)

# Crear dataset
tokenizer = AndroidCodeTokenizer()
dataset = VulnerabilityDataset(
    flows=extracted_features,
    tokenizer=tokenizer,
    labels=[0, 1, 1, 0, ...]  # 0=benigno, 1=malicioso
)

# Entrenar
loader = DataLoader(dataset, batch_size=32, shuffle=True)
optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5)

for batch in loader:
    outputs = model(**batch)
    loss = outputs["loss"]
    loss.backward()
    optimizer.step()
    optimizer.zero_grad()
```

Requisitos:
===========
- Python 3.8+
- PyTorch 1.9+ (para entrenamiento)
- numpy

Autor: Tesis - Detección de Vulnerabilidades Android
Fecha: Diciembre 2024
"""

# Importar componentes principales
from .code_tokenizer import (
    # Clases principales
    AndroidCodeTokenizer,
    TokenizedSequence,
    VocabularyBuilder,
    Token,
    TokenType,
    
    # Funciones de utilidad
    create_default_tokenizer
)

from .feature_extractor import (
    # Clases de características
    FeatureExtractor,
    ExtractedFeatures,
    SemanticFeatures,
    StructuralFeatures,
    SecurityFeatures,
    FeatureType,
    
    # Dataset builder
    DatasetBuilder,
    
    # Funciones de utilidad
    extract_features_from_flows
)

from .vulnerability_classifier import (
    # Configuración
    TransformerConfig,
    ModelSize,
    get_config_for_size,
    
    # Predicción
    VulnerabilityPrediction,
    
    # API de alto nivel
    AndroidVulnerabilityDetector,
    
    # Funciones de utilidad
    create_classifier,
    create_detector
)

# Importar componentes de PyTorch solo si está disponible
try:
    import torch
    from .vulnerability_classifier import (
        VulnerabilityClassifier,
        VulnerabilityDataset,
        Embeddings,
        MultiHeadAttention,
        FeedForward,
        TransformerLayer,
        TransformerEncoder,
        ClassificationHead
    )
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


# Versión del módulo
__version__ = "1.0.0"

# Exportar todo
__all__ = [
    # Tokenizador
    "AndroidCodeTokenizer",
    "TokenizedSequence",
    "VocabularyBuilder",
    "Token",
    "TokenType",
    "create_default_tokenizer",
    
    # Extractor de características
    "FeatureExtractor",
    "ExtractedFeatures",
    "SemanticFeatures",
    "StructuralFeatures",
    "SecurityFeatures",
    "FeatureType",
    "DatasetBuilder",
    "extract_features_from_flows",
    
    # Configuración
    "TransformerConfig",
    "ModelSize",
    "get_config_for_size",
    
    # Predicción
    "VulnerabilityPrediction",
    
    # API de alto nivel
    "AndroidVulnerabilityDetector",
    "create_classifier",
    "create_detector",
    
    # Constantes
    "TORCH_AVAILABLE",
    "__version__"
]

# Añadir componentes de PyTorch si están disponibles
if TORCH_AVAILABLE:
    __all__.extend([
        "VulnerabilityClassifier",
        "VulnerabilityDataset",
        "Embeddings",
        "MultiHeadAttention",
        "FeedForward",
        "TransformerLayer",
        "TransformerEncoder",
        "ClassificationHead"
    ])

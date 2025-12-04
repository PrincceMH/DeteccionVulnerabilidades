"""
Módulo 3: Transformer - Feature Extractor
==========================================

Este módulo extrae características de los TaintFlows detectados
en el Módulo 2 para prepararlos como entrada del modelo.

Extrae 3 tipos de características:

1. **Características Semánticas**: Del código fuente/bytecode
   - Tokens del source y sink
   - Contexto del código (clase, método)
   
2. **Características Estructurales**: De la estructura del flujo
   - Profundidad del path
   - Número de métodos intermedios
   - Complejidad del flujo
   
3. **Características de Seguridad**: Metadatos de seguridad
   - Categoría de vulnerabilidad
   - Permisos involucrados
   - Nivel de riesgo previo

Autor: Tesis - Detección de Vulnerabilidades Android
Fecha: Diciembre 2024
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple, TYPE_CHECKING
from enum import Enum, auto
import numpy as np
from abc import ABC, abstractmethod
import sys
from pathlib import Path

# Añadir path para imports relativos
sys.path.insert(0, str(Path(__file__).parent.parent))

from taint_analysis.flow_tracker import TaintFlow, FlowConfidence
from taint_analysis.sources_sinks import SourceSinkCategory


class FeatureType(Enum):
    """Tipos de características extraídas."""
    SEMANTIC = auto()      # Del código/API
    STRUCTURAL = auto()    # De la estructura del flujo
    SECURITY = auto()      # De metadatos de seguridad
    COMBINED = auto()      # Combinación de todas


@dataclass
class SemanticFeatures:
    """
    Características semánticas extraídas del código.
    
    Estas características capturan el SIGNIFICADO del código:
    qué APIs se usan, qué datos se manejan, etc.
    
    Attributes:
        source_api: API completa del source
        sink_api: API completa del sink
        source_class: Clase del source
        sink_class: Clase del sink
        source_method: Método del source
        sink_method: Método del sink
        source_tokens: Tokens del source
        sink_tokens: Tokens del sink
    """
    source_api: str
    sink_api: str
    source_class: str = ""
    sink_class: str = ""
    source_method: str = ""
    sink_method: str = ""
    source_tokens: List[str] = field(default_factory=list)
    sink_tokens: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario."""
        return {
            "source_api": self.source_api,
            "sink_api": self.sink_api,
            "source_class": self.source_class,
            "sink_class": self.sink_class,
            "source_method": self.source_method,
            "sink_method": self.sink_method,
            "source_tokens": self.source_tokens,
            "sink_tokens": self.sink_tokens
        }


@dataclass
class StructuralFeatures:
    """
    Características estructurales del flujo.
    
    Estas características capturan CÓMO fluyen los datos:
    longitud del camino, complejidad, etc.
    
    Attributes:
        path_length: Número de métodos en el path
        path_methods: Lista de métodos intermedios
        call_depth: Profundidad de llamadas
        has_conditions: Si hay bifurcaciones en el flujo
        has_loops: Si el flujo atraviesa loops
        num_classes_involved: Clases involucradas
        is_same_class: Si source y sink están en misma clase
        is_same_method: Si están en el mismo método
    """
    path_length: int = 0
    path_methods: List[str] = field(default_factory=list)
    call_depth: int = 0
    has_conditions: bool = False
    has_loops: bool = False
    num_classes_involved: int = 1
    is_same_class: bool = False
    is_same_method: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario."""
        return {
            "path_length": self.path_length,
            "path_methods": self.path_methods,
            "call_depth": self.call_depth,
            "has_conditions": self.has_conditions,
            "has_loops": self.has_loops,
            "num_classes_involved": self.num_classes_involved,
            "is_same_class": self.is_same_class,
            "is_same_method": self.is_same_method
        }
    
    def to_vector(self) -> List[float]:
        """Convierte a vector numérico para el modelo."""
        return [
            float(self.path_length),
            float(self.call_depth),
            1.0 if self.has_conditions else 0.0,
            1.0 if self.has_loops else 0.0,
            float(self.num_classes_involved),
            1.0 if self.is_same_class else 0.0,
            1.0 if self.is_same_method else 0.0
        ]


@dataclass
class SecurityFeatures:
    """
    Características de seguridad del flujo.
    
    Estas características capturan información de SEGURIDAD:
    qué tan peligroso es el flujo, qué permisos necesita, etc.
    
    Attributes:
        category: Categoría de vulnerabilidad
        risk_level: Nivel de riesgo (1-10)
        confidence: Confianza del análisis
        permissions_required: Permisos Android necesarios
        is_sensitive_source: Si el source maneja datos sensibles
        is_dangerous_sink: Si el sink puede exponer datos
        data_type: Tipo de dato que fluye (ID, LOCATION, etc.)
    """
    category: str
    risk_level: int = 5
    confidence: str = "MEDIUM"
    permissions_required: List[str] = field(default_factory=list)
    is_sensitive_source: bool = False
    is_dangerous_sink: bool = False
    data_type: str = "UNKNOWN"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario."""
        return {
            "category": self.category,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "permissions_required": self.permissions_required,
            "is_sensitive_source": self.is_sensitive_source,
            "is_dangerous_sink": self.is_dangerous_sink,
            "data_type": self.data_type
        }
    
    def to_vector(self) -> List[float]:
        """Convierte a vector numérico."""
        # Normalizar risk_level a 0-1
        risk_normalized = self.risk_level / 10.0
        
        # Mapear confidence a valor numérico
        confidence_map = {"HIGH": 1.0, "MEDIUM": 0.5, "LOW": 0.25}
        confidence_val = confidence_map.get(self.confidence, 0.5)
        
        return [
            risk_normalized,
            confidence_val,
            float(len(self.permissions_required)),
            1.0 if self.is_sensitive_source else 0.0,
            1.0 if self.is_dangerous_sink else 0.0
        ]


@dataclass
class ExtractedFeatures:
    """
    Todas las características extraídas de un TaintFlow.
    
    Esta estructura combina todas las características y las
    prepara para el modelo Transformer.
    
    Attributes:
        flow_id: ID único del flujo
        semantic: Características semánticas
        structural: Características estructurales
        security: Características de seguridad
        label: Etiqueta de clasificación (para entrenamiento)
    """
    flow_id: str
    semantic: SemanticFeatures
    structural: StructuralFeatures
    security: SecurityFeatures
    label: Optional[int] = None  # 0=benigno, 1=malicioso
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte todas las características a diccionario."""
        return {
            "flow_id": self.flow_id,
            "semantic": self.semantic.to_dict(),
            "structural": self.structural.to_dict(),
            "security": self.security.to_dict(),
            "label": self.label
        }
    
    def get_combined_vector(self) -> List[float]:
        """
        Obtiene vector combinado de características numéricas.
        
        Útil para modelos que necesitan input numérico además
        del texto tokenizado.
        """
        return self.structural.to_vector() + self.security.to_vector()


class FeatureExtractor:
    """
    Extractor principal de características de TaintFlows.
    
    Este extractor toma los TaintFlows del Módulo 2 y extrae
    todas las características necesarias para el modelo.
    
    Ejemplo de uso:
        extractor = FeatureExtractor()
        
        # Extraer características de un flujo
        features = extractor.extract(taint_flow)
        
        # Usar con el tokenizador
        tokenized = tokenizer.tokenize_flow(
            source=features.semantic.source_api,
            sink=features.semantic.sink_api,
            category=features.security.category
        )
    """
    
    # Mapeo de métodos source a tipo de dato
    SOURCE_DATA_TYPES = {
        "getDeviceId": "DEVICE_ID",
        "getLine1Number": "PHONE_NUMBER",
        "getSimSerialNumber": "SIM_ID",
        "getLastKnownLocation": "LOCATION",
        "getLatitude": "LOCATION",
        "getLongitude": "LOCATION",
        "query": "DATABASE",
        "getString": "STRING_DATA",
        "getInputStream": "INPUT_STREAM",
        "getPassword": "CREDENTIAL",
        "getSubscriberId": "IMSI"
    }
    
    # Sinks peligrosos
    DANGEROUS_SINKS = {
        "sendTextMessage", "sendDataMessage",  # SMS
        "openConnection", "connect",  # Network
        "write", "println",  # Log/File
        "loadUrl", "evaluateJavascript",  # WebView
        "startActivity", "sendBroadcast"  # IPC
    }
    
    def __init__(self):
        """Inicializa el extractor."""
        pass
    
    def _extract_semantic_features(self, flow: TaintFlow) -> SemanticFeatures:
        """
        Extrae características semánticas de un TaintFlow.
        
        Args:
            flow: TaintFlow del Módulo 2
            
        Returns:
            SemanticFeatures con información del código
        """
        # Obtener API completa (probar diferentes atributos)
        source_api = ""
        if hasattr(flow.source, 'signature'):
            source_api = flow.source.signature
        elif hasattr(flow.source, 'full_signature'):
            source_api = flow.source.full_signature
        else:
            source_api = str(flow.source)
            
        sink_api = ""
        if hasattr(flow.sink, 'signature'):
            sink_api = flow.sink.signature
        elif hasattr(flow.sink, 'full_signature'):
            sink_api = flow.sink.full_signature
        else:
            sink_api = str(flow.sink)
        
        # Extraer clase y método del source
        source_class = ""
        source_method = ""
        if hasattr(flow.source, 'class_name'):
            source_class = flow.source.class_name
        if hasattr(flow.source, 'method_name'):
            source_method = flow.source.method_name
        
        # Extraer clase y método del sink
        sink_class = ""
        sink_method = ""
        if hasattr(flow.sink, 'class_name'):
            sink_class = flow.sink.class_name
        if hasattr(flow.sink, 'method_name'):
            sink_method = flow.sink.method_name
        
        # Tokenizar para análisis
        import re
        source_tokens = re.findall(r'[A-Z][a-z]+|[a-z]+', source_api)
        sink_tokens = re.findall(r'[A-Z][a-z]+|[a-z]+', sink_api)
        
        return SemanticFeatures(
            source_api=source_api,
            sink_api=sink_api,
            source_class=source_class,
            sink_class=sink_class,
            source_method=source_method,
            sink_method=sink_method,
            source_tokens=source_tokens,
            sink_tokens=sink_tokens
        )
    
    def _extract_structural_features(self, flow: TaintFlow) -> StructuralFeatures:
        """
        Extrae características estructurales del flujo.
        
        Args:
            flow: TaintFlow del Módulo 2
            
        Returns:
            StructuralFeatures con información del path
        """
        # Obtener path de métodos
        path_methods = flow.path if hasattr(flow, 'path') and flow.path else []
        path_length = len(path_methods)
        
        # Analizar profundidad de llamadas
        call_depth = path_length
        
        # Detectar condiciones y loops (heurística basada en nombres)
        has_conditions = any(
            keyword in str(m).lower() 
            for m in path_methods 
            for keyword in ['if', 'check', 'validate', 'verify']
        )
        
        has_loops = any(
            keyword in str(m).lower() 
            for m in path_methods 
            for keyword in ['loop', 'iterate', 'foreach', 'while']
        )
        
        # Contar clases involucradas
        classes_in_path = set()
        for method in path_methods:
            if '.' in str(method):
                classes_in_path.add(str(method).rsplit('.', 1)[0])
        num_classes = len(classes_in_path) if classes_in_path else 1
        
        # Verificar si source y sink están en misma clase/método
        source_loc = flow.source_location if hasattr(flow, 'source_location') else None
        sink_loc = flow.sink_location if hasattr(flow, 'sink_location') else None
        
        is_same_class = False
        is_same_method = False
        
        if source_loc and sink_loc:
            if hasattr(source_loc, 'class_name') and hasattr(sink_loc, 'class_name'):
                is_same_class = source_loc.class_name == sink_loc.class_name
            if hasattr(source_loc, 'method_name') and hasattr(sink_loc, 'method_name'):
                is_same_method = is_same_class and source_loc.method_name == sink_loc.method_name
        
        return StructuralFeatures(
            path_length=path_length,
            path_methods=[str(m) for m in path_methods],
            call_depth=call_depth,
            has_conditions=has_conditions,
            has_loops=has_loops,
            num_classes_involved=num_classes,
            is_same_class=is_same_class,
            is_same_method=is_same_method
        )
    
    def _extract_security_features(self, flow: TaintFlow) -> SecurityFeatures:
        """
        Extrae características de seguridad del flujo.
        
        Args:
            flow: TaintFlow del Módulo 2
            
        Returns:
            SecurityFeatures con información de seguridad
        """
        # Obtener categoría
        category = str(flow.category.name) if hasattr(flow.category, 'name') else str(flow.category)
        
        # Obtener nivel de riesgo
        risk_level = flow.risk_level if hasattr(flow, 'risk_level') else 5
        
        # Obtener confianza
        confidence = "MEDIUM"
        if hasattr(flow, 'confidence'):
            if flow.confidence == FlowConfidence.HIGH:
                confidence = "HIGH"
            elif flow.confidence == FlowConfidence.LOW:
                confidence = "LOW"
        
        # Obtener permisos
        permissions = flow.permissions_required if hasattr(flow, 'permissions_required') else []
        
        # Determinar tipo de dato
        source_method = ""
        if hasattr(flow.source, 'method_name'):
            source_method = flow.source.method_name
        data_type = self.SOURCE_DATA_TYPES.get(source_method, "UNKNOWN")
        
        # Verificar si es source sensible
        is_sensitive_source = data_type != "UNKNOWN"
        
        # Verificar si es sink peligroso
        sink_method = ""
        if hasattr(flow.sink, 'method_name'):
            sink_method = flow.sink.method_name
        is_dangerous_sink = sink_method in self.DANGEROUS_SINKS
        
        return SecurityFeatures(
            category=category,
            risk_level=risk_level,
            confidence=confidence,
            permissions_required=list(permissions) if permissions else [],
            is_sensitive_source=is_sensitive_source,
            is_dangerous_sink=is_dangerous_sink,
            data_type=data_type
        )
    
    def extract(self, flow: TaintFlow) -> ExtractedFeatures:
        """
        Extrae todas las características de un TaintFlow.
        
        Esta es la función principal del extractor.
        
        Args:
            flow: TaintFlow detectado en el Módulo 2
            
        Returns:
            ExtractedFeatures con todas las características
        
        Example:
            >>> extractor = FeatureExtractor()
            >>> features = extractor.extract(taint_flow)
            >>> print(features.semantic.source_api)
            "TelephonyManager.getDeviceId"
            >>> print(features.security.risk_level)
            9
        """
        return ExtractedFeatures(
            flow_id=flow.flow_id if hasattr(flow, 'flow_id') else "unknown",
            semantic=self._extract_semantic_features(flow),
            structural=self._extract_structural_features(flow),
            security=self._extract_security_features(flow)
        )
    
    def extract_batch(self, flows: List[TaintFlow]) -> List[ExtractedFeatures]:
        """
        Extrae características de múltiples flujos.
        
        Args:
            flows: Lista de TaintFlows
            
        Returns:
            Lista de ExtractedFeatures
        """
        return [self.extract(flow) for flow in flows]
    
    def prepare_for_model(
        self, 
        features: ExtractedFeatures
    ) -> Dict[str, Any]:
        """
        Prepara las características para entrada del modelo.
        
        Combina características semánticas (para tokenización)
        con características numéricas (para concatenación).
        
        Args:
            features: Características extraídas
            
        Returns:
            Diccionario listo para el modelo con:
            - 'source': API source para tokenizar
            - 'sink': API sink para tokenizar
            - 'category': Categoría de vulnerabilidad
            - 'risk_level': Nivel de riesgo
            - 'permissions': Permisos involucrados
            - 'numeric_features': Vector de características numéricas
        """
        return {
            "source": features.semantic.source_api,
            "sink": features.semantic.sink_api,
            "category": features.security.category,
            "risk_level": "HIGH" if features.security.risk_level >= 7 else (
                "MEDIUM" if features.security.risk_level >= 4 else "LOW"
            ),
            "permissions": features.security.permissions_required,
            "numeric_features": features.get_combined_vector(),
            "flow_id": features.flow_id
        }


class DatasetBuilder:
    """
    Construye datasets para entrenamiento y evaluación.
    
    Toma flujos extraídos del Módulo 2 y los convierte
    en un dataset listo para entrenar el modelo.
    
    Ejemplo:
        builder = DatasetBuilder()
        
        # Añadir flujos con etiquetas
        builder.add_flow(flow, label=1)  # 1 = malicioso
        builder.add_flow(flow, label=0)  # 0 = benigno
        
        # Obtener dataset
        X, y = builder.build()
    """
    
    def __init__(self, feature_extractor: Optional[FeatureExtractor] = None):
        """
        Inicializa el builder.
        
        Args:
            feature_extractor: Extractor a usar (o crea uno nuevo)
        """
        self.extractor = feature_extractor or FeatureExtractor()
        self.samples: List[Tuple[ExtractedFeatures, int]] = []
    
    def add_flow(self, flow: TaintFlow, label: int):
        """
        Añade un flujo al dataset.
        
        Args:
            flow: TaintFlow a añadir
            label: 0=benigno, 1=malicioso
        """
        features = self.extractor.extract(flow)
        features.label = label
        self.samples.append((features, label))
    
    def add_flows(self, flows: List[TaintFlow], labels: List[int]):
        """
        Añade múltiples flujos al dataset.
        
        Args:
            flows: Lista de TaintFlows
            labels: Lista de etiquetas correspondientes
        """
        for flow, label in zip(flows, labels):
            self.add_flow(flow, label)
    
    def build(self) -> Tuple[List[ExtractedFeatures], List[int]]:
        """
        Construye el dataset final.
        
        Returns:
            Tupla de (features, labels)
        """
        features = [s[0] for s in self.samples]
        labels = [s[1] for s in self.samples]
        return features, labels
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas del dataset.
        
        Returns:
            Diccionario con estadísticas
        """
        if not self.samples:
            return {"total": 0}
        
        labels = [s[1] for s in self.samples]
        categories = {}
        
        for features, _ in self.samples:
            cat = features.security.category
            categories[cat] = categories.get(cat, 0) + 1
        
        return {
            "total": len(self.samples),
            "malicious": sum(labels),
            "benign": len(labels) - sum(labels),
            "categories": categories,
            "balance_ratio": sum(labels) / len(labels) if labels else 0
        }


# Función de utilidad
def extract_features_from_flows(flows: List[TaintFlow]) -> List[ExtractedFeatures]:
    """
    Función de conveniencia para extraer características.
    
    Args:
        flows: Lista de TaintFlows del Módulo 2
        
    Returns:
        Lista de características extraídas
    """
    extractor = FeatureExtractor()
    return extractor.extract_batch(flows)

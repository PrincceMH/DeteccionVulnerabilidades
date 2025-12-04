from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime
import json

from androguard.core.apk import APK

from .sources_sinks import SourcesSinksDatabase, SourceSinkCategory
from .flow_tracker import (
    FlowTracker,
    TaintFlow,
    BasicFlowTrackingStrategy,
    InterproceduralFlowTrackingStrategy,
    FlowConfidence
)


@dataclass
class ExtractionConfig:
    """
    Configuración para la extracción de flujos.
    
    Attributes:
        use_interprocedural: Si usar análisis interprocedural (más lento pero completo)
        max_depth: Profundidad máxima para análisis interprocedural
        min_confidence: Confianza mínima para reportar flujos
        categories_filter: Categorías a buscar (None = todas)
        include_low_risk: Si incluir flujos de bajo riesgo
    """
    use_interprocedural: bool = True
    max_depth: int = 5
    min_confidence: FlowConfidence = FlowConfidence.LOW
    categories_filter: Optional[List[SourceSinkCategory]] = None
    include_low_risk: bool = True
    min_risk_level: int = 1


@dataclass
class ExtractionResult:
    """
    Resultado de la extracción de flujos de un APK.
    
    Contiene todos los flujos encontrados junto con metadatos
    y estadísticas del análisis.
    """
    # Información del APK
    apk_path: str
    package_name: str
    apk_hash: str
    
    # Flujos encontrados
    flows: List[TaintFlow] = field(default_factory=list)
    
    # Metadatos del análisis
    extraction_time: str = ""
    extraction_duration_ms: int = 0
    config_used: Optional[ExtractionConfig] = None
    
    # Estadísticas
    statistics: Dict[str, Any] = field(default_factory=dict)
    
    # Errores encontrados
    errors: List[str] = field(default_factory=list)
    
    @property
    def total_flows(self) -> int:
        """Número total de flujos encontrados."""
        return len(self.flows)
    
    @property
    def high_risk_flows(self) -> List[TaintFlow]:
        """Flujos de alto riesgo (risk >= 7)."""
        return [f for f in self.flows if f.is_high_risk]
    
    @property
    def critical_flows(self) -> List[TaintFlow]:
        """Flujos críticos (risk >= 8 y confianza HIGH)."""
        return [
            f for f in self.flows 
            if f.risk_level >= 8 and f.confidence == FlowConfidence.HIGH
        ]
    
    def get_flows_by_category(self, category: SourceSinkCategory) -> List[TaintFlow]:
        """Obtiene flujos de una categoría específica."""
        return [f for f in self.flows if f.category == category]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el resultado a diccionario para serialización."""
        return {
            "apk_info": {
                "path": self.apk_path,
                "package_name": self.package_name,
                "hash": self.apk_hash
            },
            "analysis_info": {
                "extraction_time": self.extraction_time,
                "duration_ms": self.extraction_duration_ms,
                "config": {
                    "use_interprocedural": self.config_used.use_interprocedural if self.config_used else False,
                    "max_depth": self.config_used.max_depth if self.config_used else 5
                } if self.config_used else None
            },
            "summary": {
                "total_flows": self.total_flows,
                "high_risk_count": len(self.high_risk_flows),
                "critical_count": len(self.critical_flows)
            },
            "statistics": self.statistics,
            "flows": [f.to_dict() for f in self.flows],
            "errors": self.errors
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convierte a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    def save_to_file(self, output_path: Path) -> None:
        """Guarda el resultado en un archivo JSON."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(self.to_json())


class FlowExtractor:
    """
    Extractor principal de flujos de datos.
    
    Esta clase es el punto de entrada principal para el Módulo 2.
    Coordina todo el proceso de extracción de flujos de un APK.
    
    Implementa Facade Pattern para ocultar la complejidad del sistema
    de taint analysis.
    
    Usage:
        >>> extractor = FlowExtractor()
        >>> result = extractor.extract("app.apk")
        >>> print(f"Encontrados {result.total_flows} flujos")
        >>> for flow in result.high_risk_flows:
        ...     print(flow)
    
    Example con configuración:
        >>> config = ExtractionConfig(
        ...     use_interprocedural=True,
        ...     min_risk_level=5
        ... )
        >>> extractor = FlowExtractor(config)
        >>> result = extractor.extract("app.apk")
    """
    
    def __init__(self, config: Optional[ExtractionConfig] = None):
        """
        Inicializa el extractor.
        
        Args:
            config: Configuración de extracción (opcional)
        """
        self.config = config or ExtractionConfig()
        self._sources_db = SourcesSinksDatabase()
        self._tracker = self._create_tracker()
    
    def _create_tracker(self) -> FlowTracker:
        """
        Factory Method: Crea el tracker según la configuración.
        """
        if self.config.use_interprocedural:
            strategy = InterproceduralFlowTrackingStrategy(
                max_depth=self.config.max_depth
            )
        else:
            strategy = BasicFlowTrackingStrategy()
        
        return FlowTracker(
            strategy=strategy,
            sources_db=self._sources_db
        )
    
    def extract(self, apk_path: str | Path) -> ExtractionResult:
        """
        Extrae todos los flujos de un APK.
        
        Este es el método principal. Ejecuta el proceso completo:
        1. Carga el APK
        2. Extrae flujos con taint analysis
        3. Filtra según configuración
        4. Genera estadísticas
        5. Retorna resultado estructurado
        
        Args:
            apk_path: Ruta al archivo APK
            
        Returns:
            ExtractionResult con todos los flujos y metadatos
        """
        apk_path = Path(apk_path)
        start_time = datetime.now()
        
        # Inicializar resultado
        result = ExtractionResult(
            apk_path=str(apk_path),
            package_name="",
            apk_hash="",
            extraction_time=start_time.isoformat(),
            config_used=self.config
        )
        
        try:
            # Paso 1: Cargar APK y obtener metadatos
            apk = APK(str(apk_path))
            result.package_name = apk.get_package() or "unknown"
            result.apk_hash = self._calculate_hash(apk_path)
            
            # Paso 2: Extraer flujos
            flows = self._tracker.track(apk_path)
            
            # Paso 3: Filtrar flujos según configuración
            filtered_flows = self._filter_flows(flows)
            result.flows = filtered_flows
            
            # Paso 4: Generar estadísticas
            result.statistics = self._tracker.get_statistics(filtered_flows)
            
            # Agregar estadísticas adicionales
            result.statistics["filtered_out"] = len(flows) - len(filtered_flows)
            result.statistics["by_risk_level"] = self._count_by_risk_level(filtered_flows)
            
        except Exception as e:
            result.errors.append(f"Error durante extracción: {str(e)}")
        
        # Calcular duración
        end_time = datetime.now()
        result.extraction_duration_ms = int((end_time - start_time).total_seconds() * 1000)
        
        return result
    
    def extract_batch(self, apk_paths: List[Path]) -> List[ExtractionResult]:
        """
        Extrae flujos de múltiples APKs.
        
        Args:
            apk_paths: Lista de rutas a archivos APK
            
        Returns:
            Lista de resultados de extracción
        """
        results = []
        for apk_path in apk_paths:
            result = self.extract(apk_path)
            results.append(result)
        return results
    
    def _filter_flows(self, flows: List[TaintFlow]) -> List[TaintFlow]:
        """
        Filtra flujos según la configuración.
        """
        filtered = []
        
        for flow in flows:
            # Filtrar por confianza mínima
            if self._confidence_value(flow.confidence) < self._confidence_value(self.config.min_confidence):
                continue
            
            # Filtrar por categorías
            if self.config.categories_filter:
                if flow.category not in self.config.categories_filter:
                    continue
            
            # Filtrar por nivel de riesgo
            if not self.config.include_low_risk and flow.risk_level < 5:
                continue
            
            if flow.risk_level < self.config.min_risk_level:
                continue
            
            filtered.append(flow)
        
        return filtered
    
    @staticmethod
    def _confidence_value(confidence: FlowConfidence) -> int:
        """Convierte confianza a valor numérico para comparación."""
        mapping = {
            FlowConfidence.LOW: 1,
            FlowConfidence.MEDIUM: 2,
            FlowConfidence.HIGH: 3
        }
        return mapping.get(confidence, 0)
    
    @staticmethod
    def _calculate_hash(file_path: Path) -> str:
        """Calcula hash SHA256 del archivo."""
        import hashlib
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()[:16]
    
    @staticmethod
    def _count_by_risk_level(flows: List[TaintFlow]) -> Dict[str, int]:
        """Cuenta flujos por nivel de riesgo."""
        counts = {
            "critical (9-10)": 0,
            "high (7-8)": 0,
            "medium (5-6)": 0,
            "low (1-4)": 0
        }
        
        for flow in flows:
            risk = flow.risk_level
            if risk >= 9:
                counts["critical (9-10)"] += 1
            elif risk >= 7:
                counts["high (7-8)"] += 1
            elif risk >= 5:
                counts["medium (5-6)"] += 1
            else:
                counts["low (1-4)"] += 1
        
        return counts
    
    def get_sources_sinks_info(self) -> Dict[str, Any]:
        """
        Retorna información sobre la base de datos de sources/sinks.
        
        Útil para debugging y documentación.
        """
        return self._sources_db.get_statistics()
    
    def update_config(self, **kwargs) -> None:
        """
        Actualiza la configuración del extractor.
        
        Args:
            **kwargs: Campos de ExtractionConfig a actualizar
        """
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        
        # Recrear tracker con nueva configuración
        self._tracker = self._create_tracker()


# ============================================================================
# Funciones de conveniencia para uso rápido
# ============================================================================

def extract_flows(apk_path: str | Path) -> ExtractionResult:
    """
    Función de conveniencia para extraer flujos rápidamente.
    
    Usage:
        >>> from src.taint_analysis import extract_flows
        >>> result = extract_flows("app.apk")
        >>> print(result.total_flows)
    """
    extractor = FlowExtractor()
    return extractor.extract(apk_path)


def extract_flows_basic(apk_path: str | Path) -> ExtractionResult:
    """
    Extracción rápida usando solo análisis básico (más rápido).
    """
    config = ExtractionConfig(use_interprocedural=False)
    extractor = FlowExtractor(config)
    return extractor.extract(apk_path)


def extract_high_risk_only(apk_path: str | Path) -> ExtractionResult:
    """
    Extrae solo flujos de alto riesgo.
    """
    config = ExtractionConfig(
        min_risk_level=7,
        min_confidence=FlowConfidence.MEDIUM
    )
    extractor = FlowExtractor(config)
    return extractor.extract(apk_path)

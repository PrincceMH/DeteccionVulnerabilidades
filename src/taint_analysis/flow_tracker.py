from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any, Callable
from enum import Enum, auto
from abc import ABC, abstractmethod
from pathlib import Path
import hashlib

from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis, MethodAnalysis, ClassAnalysis

from .sources_sinks import (
    SourcesSinksDatabase, 
    SourceSink, 
    SourceSinkCategory,
    SourceSinkType
)


class FlowConfidence(Enum):
    """
    Nivel de confianza del flujo detectado.
    
    Indica qué tan seguro está el análisis de que el flujo existe.
    """
    HIGH = auto()      # Flujo directo confirmado
    MEDIUM = auto()    # Flujo probable con algunas incertidumbres
    LOW = auto()       # Flujo posible pero no confirmado


@dataclass
class CodeLocation:
    """
    Ubicación exacta en el código donde ocurre algo.
    
    Attributes:
        class_name: Nombre completo de la clase
        method_name: Nombre del método
        line_number: Número de línea (si disponible)
        instruction_index: Índice de la instrucción en el bytecode
    """
    class_name: str
    method_name: str
    line_number: Optional[int] = None
    instruction_index: Optional[int] = None
    
    @property
    def short_class_name(self) -> str:
        """Retorna nombre corto de la clase."""
        return self.class_name.split('.')[-1].rstrip(';').lstrip('L')
    
    def __str__(self) -> str:
        """Representación legible de la ubicación."""
        loc = f"{self.short_class_name}.{self.method_name}()"
        if self.line_number:
            loc += f" [línea {self.line_number}]"
        return loc


@dataclass
class TaintFlow:
    """
    Representa un flujo de datos detectado (source → sink).
    
    Esta es la estructura principal que se pasa al Transformer
    para clasificación.
    
    Attributes:
        flow_id: Identificador único del flujo
        source: API source de donde viene el dato
        sink: API sink a donde va el dato
        source_location: Ubicación del source en el código
        sink_location: Ubicación del sink en el código
        path: Camino de métodos entre source y sink
        category: Categoría de vulnerabilidad
        confidence: Nivel de confianza del análisis
        permissions_required: Permisos Android involucrados
        context: Información contextual adicional
    """
    flow_id: str
    source: SourceSink
    sink: SourceSink
    source_location: CodeLocation
    sink_location: CodeLocation
    path: List[str] = field(default_factory=list)
    category: SourceSinkCategory = SourceSinkCategory.NETWORK_LEAK
    confidence: FlowConfidence = FlowConfidence.MEDIUM
    permissions_required: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Genera ID único si no se proporcionó."""
        if not self.flow_id:
            self.flow_id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Genera un ID único basado en el contenido del flujo."""
        content = (
            f"{self.source.full_name}"
            f"{self.sink.full_name}"
            f"{self.source_location}"
            f"{self.sink_location}"
        )
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    @property
    def risk_level(self) -> int:
        """Calcula el nivel de riesgo combinado (1-10)."""
        # Promedio ponderado de riesgos de source y sink
        source_weight = 0.4
        sink_weight = 0.6
        return int(
            self.source.risk_level * source_weight + 
            self.sink.risk_level * sink_weight
        )
    
    @property
    def is_high_risk(self) -> bool:
        """Indica si es un flujo de alto riesgo."""
        return self.risk_level >= 7
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el flujo a diccionario para serialización."""
        return {
            "flow_id": self.flow_id,
            "source": {
                "api": self.source.full_name,
                "description": self.source.description,
                "risk_level": self.source.risk_level
            },
            "sink": {
                "api": self.sink.full_name,
                "description": self.sink.description,
                "risk_level": self.sink.risk_level
            },
            "source_location": str(self.source_location),
            "sink_location": str(self.sink_location),
            "path": self.path,
            "category": self.category.name,
            "confidence": self.confidence.name,
            "risk_level": self.risk_level,
            "permissions_required": self.permissions_required,
            "context": self.context
        }
    
    def __str__(self) -> str:
        """Representación legible del flujo."""
        return (
            f"TaintFlow[{self.flow_id}]: "
            f"{self.source.method_name} → {self.sink.method_name} "
            f"({self.category.name}, risk={self.risk_level})"
        )


class TaintFlowBuilder:
    """
    Builder Pattern para construir objetos TaintFlow.
    
    Facilita la construcción paso a paso de flujos complejos.
    
    Usage:
        >>> flow = (TaintFlowBuilder()
        ...     .with_source(source_api)
        ...     .with_sink(sink_api)
        ...     .at_source_location(class_name, method_name)
        ...     .at_sink_location(class_name, method_name)
        ...     .with_path(["method1", "method2"])
        ...     .build())
    """
    
    def __init__(self):
        """Inicializa el builder con valores por defecto."""
        self._source: Optional[SourceSink] = None
        self._sink: Optional[SourceSink] = None
        self._source_location: Optional[CodeLocation] = None
        self._sink_location: Optional[CodeLocation] = None
        self._path: List[str] = []
        self._confidence: FlowConfidence = FlowConfidence.MEDIUM
        self._permissions: List[str] = []
        self._context: Dict[str, Any] = {}
    
    def with_source(self, source: SourceSink) -> 'TaintFlowBuilder':
        """Establece el source del flujo."""
        self._source = source
        return self
    
    def with_sink(self, sink: SourceSink) -> 'TaintFlowBuilder':
        """Establece el sink del flujo."""
        self._sink = sink
        return self
    
    def at_source_location(
        self, 
        class_name: str, 
        method_name: str,
        line_number: Optional[int] = None
    ) -> 'TaintFlowBuilder':
        """Establece la ubicación del source."""
        self._source_location = CodeLocation(
            class_name=class_name,
            method_name=method_name,
            line_number=line_number
        )
        return self
    
    def at_sink_location(
        self, 
        class_name: str, 
        method_name: str,
        line_number: Optional[int] = None
    ) -> 'TaintFlowBuilder':
        """Establece la ubicación del sink."""
        self._sink_location = CodeLocation(
            class_name=class_name,
            method_name=method_name,
            line_number=line_number
        )
        return self
    
    def with_path(self, path: List[str]) -> 'TaintFlowBuilder':
        """Establece el camino entre source y sink."""
        self._path = path
        return self
    
    def with_confidence(self, confidence: FlowConfidence) -> 'TaintFlowBuilder':
        """Establece el nivel de confianza."""
        self._confidence = confidence
        return self
    
    def with_permissions(self, permissions: List[str]) -> 'TaintFlowBuilder':
        """Establece los permisos involucrados."""
        self._permissions = permissions
        return self
    
    def with_context(self, key: str, value: Any) -> 'TaintFlowBuilder':
        """Agrega información contextual."""
        self._context[key] = value
        return self
    
    def build(self) -> TaintFlow:
        """
        Construye el objeto TaintFlow.
        
        Raises:
            ValueError: Si faltan campos obligatorios.
        """
        if not self._source:
            raise ValueError("Source es obligatorio")
        if not self._sink:
            raise ValueError("Sink es obligatorio")
        if not self._source_location:
            raise ValueError("Source location es obligatorio")
        if not self._sink_location:
            raise ValueError("Sink location es obligatorio")
        
        # Determinar categoría (usar la del sink como principal)
        category = self._sink.category
        
        # Combinar permisos de source y sink
        all_permissions = list(set(
            list(self._source.required_permissions) + 
            list(self._sink.required_permissions) +
            self._permissions
        ))
        
        return TaintFlow(
            flow_id="",  # Se generará automáticamente
            source=self._source,
            sink=self._sink,
            source_location=self._source_location,
            sink_location=self._sink_location,
            path=self._path,
            category=category,
            confidence=self._confidence,
            permissions_required=all_permissions,
            context=self._context
        )


class IFlowTrackingStrategy(ABC):
    """
    Interface para estrategias de tracking de flujos.
    Implementa Strategy Pattern.
    """
    
    @abstractmethod
    def track_flows(
        self, 
        analysis: Analysis,
        sources_db: SourcesSinksDatabase
    ) -> List[TaintFlow]:
        """
        Rastrea flujos en el análisis dado.
        
        Args:
            analysis: Objeto Analysis de Androguard
            sources_db: Base de datos de sources/sinks
            
        Returns:
            Lista de flujos detectados
        """
        pass


class BasicFlowTrackingStrategy(IFlowTrackingStrategy):
    """
    Estrategia básica de tracking: busca sources y sinks en el mismo método.
    
    Esta es la estrategia más simple y rápida, detecta flujos directos
    donde source y sink están en el mismo método.
    """
    
    def track_flows(
        self, 
        analysis: Analysis,
        sources_db: SourcesSinksDatabase
    ) -> List[TaintFlow]:
        """Implementación de tracking básico."""
        flows: List[TaintFlow] = []
        
        # Obtener métodos source y sink para búsqueda rápida
        source_methods = sources_db.get_source_methods()
        sink_methods = sources_db.get_sink_methods()
        
        # Iterar sobre todas las clases
        for class_analysis in analysis.get_classes():
            class_name = class_analysis.name
            
            # Iterar sobre todos los métodos de la clase
            for method_analysis in class_analysis.get_methods():
                if method_analysis.is_external():
                    continue
                
                method_name = method_analysis.name
                
                # Buscar sources y sinks en este método
                sources_found = []
                sinks_found = []
                
                # Analizar instrucciones del método
                method = method_analysis.get_method()
                if method is None:
                    continue
                
                try:
                    # Obtener las llamadas a métodos dentro de este método
                    for _, call, _ in method_analysis.get_xref_to():
                        called_class = call.class_name
                        called_method = call.name
                        
                        # Verificar si es source
                        if called_method in source_methods:
                            source_info = sources_db.get_source(called_class, called_method)
                            if source_info:
                                sources_found.append((source_info, called_class, called_method))
                        
                        # Verificar si es sink
                        if called_method in sink_methods:
                            sink_info = sources_db.get_sink(called_class, called_method)
                            if sink_info:
                                sinks_found.append((sink_info, called_class, called_method))
                except Exception:
                    continue
                
                # Crear flujos para cada combinación source-sink
                for source_info, src_class, src_method in sources_found:
                    for sink_info, snk_class, snk_method in sinks_found:
                        flow = (TaintFlowBuilder()
                            .with_source(source_info)
                            .with_sink(sink_info)
                            .at_source_location(class_name, method_name)
                            .at_sink_location(class_name, method_name)
                            .with_path([src_method, method_name, snk_method])
                            .with_confidence(FlowConfidence.HIGH)
                            .with_context("same_method", True)
                            .build())
                        flows.append(flow)
        
        return flows


class InterproceduralFlowTrackingStrategy(IFlowTrackingStrategy):
    """
    Estrategia avanzada: rastrea flujos entre métodos diferentes.
    
    Usa análisis de call graph para encontrar flujos que atraviesan
    múltiples métodos.
    """
    
    def __init__(self, max_depth: int = 5):
        """
        Inicializa la estrategia.
        
        Args:
            max_depth: Profundidad máxima de búsqueda en el call graph
        """
        self.max_depth = max_depth
    
    def track_flows(
        self, 
        analysis: Analysis,
        sources_db: SourcesSinksDatabase
    ) -> List[TaintFlow]:
        """Implementación de tracking interprocedural."""
        flows: List[TaintFlow] = []
        
        source_methods = sources_db.get_source_methods()
        sink_methods = sources_db.get_sink_methods()
        
        # Mapear métodos que contienen sources y sinks
        methods_with_sources: Dict[str, List[Tuple[SourceSink, str]]] = {}
        methods_with_sinks: Dict[str, List[Tuple[SourceSink, str]]] = {}
        
        # Primera pasada: identificar métodos con sources/sinks
        for class_analysis in analysis.get_classes():
            class_name = class_analysis.name
            
            for method_analysis in class_analysis.get_methods():
                if method_analysis.is_external():
                    continue
                
                method_key = f"{class_name}->{method_analysis.name}"
                
                try:
                    for _, call, _ in method_analysis.get_xref_to():
                        called_method = call.name
                        called_class = call.class_name
                        
                        if called_method in source_methods:
                            source_info = sources_db.get_source(called_class, called_method)
                            if source_info:
                                if method_key not in methods_with_sources:
                                    methods_with_sources[method_key] = []
                                methods_with_sources[method_key].append((source_info, class_name))
                        
                        if called_method in sink_methods:
                            sink_info = sources_db.get_sink(called_class, called_method)
                            if sink_info:
                                if method_key not in methods_with_sinks:
                                    methods_with_sinks[method_key] = []
                                methods_with_sinks[method_key].append((sink_info, class_name))
                except Exception:
                    continue
        
        # Segunda pasada: buscar conexiones via call graph
        for source_method_key, sources in methods_with_sources.items():
            source_class, source_method = self._parse_method_key(source_method_key)
            
            # Buscar sinks alcanzables desde este método
            reachable_sinks = self._find_reachable_sinks(
                analysis, 
                source_method_key, 
                methods_with_sinks
            )
            
            for sink_method_key, path in reachable_sinks:
                if sink_method_key not in methods_with_sinks:
                    continue
                
                sink_class, sink_method = self._parse_method_key(sink_method_key)
                
                for source_info, src_loc_class in sources:
                    for sink_info, snk_loc_class in methods_with_sinks[sink_method_key]:
                        flow = (TaintFlowBuilder()
                            .with_source(source_info)
                            .with_sink(sink_info)
                            .at_source_location(src_loc_class, source_method)
                            .at_sink_location(snk_loc_class, sink_method)
                            .with_path(path)
                            .with_confidence(
                                FlowConfidence.HIGH if len(path) <= 2 
                                else FlowConfidence.MEDIUM
                            )
                            .with_context("interprocedural", True)
                            .with_context("path_length", len(path))
                            .build())
                        flows.append(flow)
        
        return flows
    
    def _parse_method_key(self, key: str) -> Tuple[str, str]:
        """Parsea una clave de método en clase y nombre."""
        if "->" in key:
            parts = key.split("->")
            return parts[0], parts[1]
        return "", key
    
    def _find_reachable_sinks(
        self,
        analysis: Analysis,
        start_method: str,
        methods_with_sinks: Dict[str, List]
    ) -> List[Tuple[str, List[str]]]:
        """
        Encuentra métodos con sinks alcanzables desde el método dado.
        
        Returns:
            Lista de tuplas (método_sink, path)
        """
        reachable = []
        visited = set()
        
        def dfs(current: str, path: List[str], depth: int):
            if depth > self.max_depth:
                return
            if current in visited:
                return
            
            visited.add(current)
            
            # Si este método tiene sinks, agregarlo
            if current in methods_with_sinks:
                reachable.append((current, path.copy()))
            
            # Continuar búsqueda en métodos llamados
            class_name, method_name = self._parse_method_key(current)
            
            try:
                class_analysis = analysis.get_class_analysis(class_name)
                if class_analysis:
                    for method_analysis in class_analysis.get_methods():
                        if method_analysis.name == method_name:
                            for _, call, _ in method_analysis.get_xref_to():
                                next_key = f"{call.class_name}->{call.name}"
                                dfs(next_key, path + [call.name], depth + 1)
            except Exception:
                pass
        
        start_parts = self._parse_method_key(start_method)
        dfs(start_method, [start_parts[1]], 0)
        
        return reachable


class FlowTracker:
    """
    Rastreador principal de flujos de datos.
    
    Implementa el Facade Pattern para simplificar el uso del sistema
    de tracking. Coordina las diferentes estrategias de tracking.
    
    Usage:
        >>> tracker = FlowTracker()
        >>> flows = tracker.track(apk_path)
        >>> for flow in flows:
        ...     print(flow)
    """
    
    def __init__(
        self,
        strategy: Optional[IFlowTrackingStrategy] = None,
        sources_db: Optional[SourcesSinksDatabase] = None
    ):
        """
        Inicializa el tracker.
        
        Args:
            strategy: Estrategia de tracking a usar (default: BasicFlowTrackingStrategy)
            sources_db: Base de datos de sources/sinks
        """
        self._strategy = strategy or BasicFlowTrackingStrategy()
        self._sources_db = sources_db or SourcesSinksDatabase()
        self._observers: List[Callable[[TaintFlow], None]] = []
    
    def set_strategy(self, strategy: IFlowTrackingStrategy) -> None:
        """Cambia la estrategia de tracking."""
        self._strategy = strategy
    
    def add_observer(self, callback: Callable[[TaintFlow], None]) -> None:
        """
        Agrega un observer para ser notificado de flujos encontrados.
        Implementa Observer Pattern.
        """
        self._observers.append(callback)
    
    def remove_observer(self, callback: Callable[[TaintFlow], None]) -> None:
        """Remueve un observer."""
        if callback in self._observers:
            self._observers.remove(callback)
    
    def _notify_observers(self, flow: TaintFlow) -> None:
        """Notifica a todos los observers de un nuevo flujo."""
        for observer in self._observers:
            observer(flow)
    
    def track(self, apk_path: Path) -> List[TaintFlow]:
        """
        Rastrea flujos en un APK.
        
        Args:
            apk_path: Ruta al archivo APK
            
        Returns:
            Lista de flujos detectados
        """
        # Cargar y analizar el APK
        apk = APK(str(apk_path))
        
        # Obtener todos los DEX y crear análisis
        all_flows: List[TaintFlow] = []
        
        # En Androguard 4.x, get_all_dex() retorna bytes
        # Necesitamos crear objetos DEX desde esos bytes
        dex_files = apk.get_all_dex()
        
        for dex_bytes in dex_files:
            try:
                # Crear objeto DEX desde bytes
                dex = DEX(dex_bytes)
                
                # Crear análisis del DEX
                analysis = Analysis()
                analysis.add(dex)
                analysis.create_xref()
                
                # Ejecutar tracking con la estrategia configurada
                flows = self._strategy.track_flows(analysis, self._sources_db)
                
                # Agregar contexto del APK
                for flow in flows:
                    flow.context["apk_path"] = str(apk_path)
                    flow.context["package_name"] = apk.get_package()
                    self._notify_observers(flow)
                
                all_flows.extend(flows)
                
            except Exception as e:
                # Log del error pero continuar con otros DEX
                print(f"Error analizando DEX: {e}")
                continue
        
        return all_flows
    
    def track_from_analysis(self, analysis: Analysis) -> List[TaintFlow]:
        """
        Rastrea flujos desde un objeto Analysis existente.
        
        Útil cuando ya se tiene el análisis de Androguard.
        """
        flows = self._strategy.track_flows(analysis, self._sources_db)
        for flow in flows:
            self._notify_observers(flow)
        return flows
    
    def get_statistics(self, flows: List[TaintFlow]) -> Dict[str, Any]:
        """
        Genera estadísticas de los flujos encontrados.
        
        Args:
            flows: Lista de flujos a analizar
            
        Returns:
            Diccionario con estadísticas
        """
        stats = {
            "total_flows": len(flows),
            "high_risk_flows": sum(1 for f in flows if f.is_high_risk),
            "by_category": {},
            "by_confidence": {},
            "unique_sources": set(),
            "unique_sinks": set()
        }
        
        for flow in flows:
            # Por categoría
            cat_name = flow.category.name
            stats["by_category"][cat_name] = stats["by_category"].get(cat_name, 0) + 1
            
            # Por confianza
            conf_name = flow.confidence.name
            stats["by_confidence"][conf_name] = stats["by_confidence"].get(conf_name, 0) + 1
            
            # Sources y sinks únicos
            stats["unique_sources"].add(flow.source.full_name)
            stats["unique_sinks"].add(flow.sink.full_name)
        
        # Convertir sets a listas para serialización
        stats["unique_sources"] = list(stats["unique_sources"])
        stats["unique_sinks"] = list(stats["unique_sinks"])
        
        return stats

"""
MÓDULO 2: Análisis Taint Especializado
Implementa análisis flow-sensitive de flujos de información Android
"""

import logging
from typing import Dict, List, Any, Set, Tuple
from dataclasses import dataclass
from pathlib import Path
import networkx as nx


@dataclass
class TaintFlow:
    """Representa un flujo de información desde source hasta sink"""
    source: str
    sink: str
    path: List[str]
    api_sequence: List[str]
    permissions: List[str]
    components: List[str]
    criticality_score: float = 0.0
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class TaintAnalyzer:
    """
    Analizador de flujos taint especializado para Android
    - Flow-sensitive analysis
    - Context-sensitive analysis  
    - Lifecycle-aware
    - Inter-component communication
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: Configuración del análisis taint
        """
        self.config = config
        self.logger = logging.getLogger("TaintAnalyzer")
        
        # Sources y Sinks críticos Android
        self.sources = self._load_sources(config.get('sources', []))
        self.sinks = self._load_sinks(config.get('sinks', []))
        
        # Configuración de análisis
        self.flow_sensitive = config.get('flow_sensitive', True)
        self.context_sensitive = config.get('context_sensitive', True)
        self.field_sensitive = config.get('field_sensitive', True)
        self.lifecycle_aware = config.get('lifecycle_aware', True)
        self.max_depth = config.get('max_depth', 10)
        self.timeout = config.get('timeout_seconds', 300)
        
        self.logger.info(f"Taint Analyzer inicializado: {len(self.sources)} sources, "
                        f"{len(self.sinks)} sinks")
    
    def analyze(
        self,
        jimple_code: Dict[str, Any],
        manifest: Dict[str, Any],
        cfg: Dict[str, Any]
    ) -> List[TaintFlow]:
        """
        Analiza flujos taint en la aplicación
        
        Args:
            jimple_code: Código Jimple desde preprocesamiento
            manifest: Datos del AndroidManifest
            cfg: Control Flow Graphs
            
        Returns:
            Lista de flujos taint detectados
        """
        self.logger.info("Iniciando análisis taint...")
        
        flows = []
        
        try:
            # 1. Identificar puntos de entrada (entry points)
            entry_points = self._identify_entry_points(manifest, cfg)
            self.logger.info(f"Identificados {len(entry_points)} puntos de entrada")
            
            # 2. Construir grafo de flujo de datos
            data_flow_graph = self._build_data_flow_graph(jimple_code, cfg)
            
            # 3. Análisis source-to-sink
            for source in self.sources:
                for sink in self.sinks:
                    paths = self._find_paths(source, sink, data_flow_graph)
                    
                    for path in paths:
                        flow = self._create_taint_flow(
                            source, sink, path, manifest, jimple_code
                        )
                        flows.append(flow)
            
            self.logger.info(f"Detectados {len(flows)} flujos taint potenciales")
            
            # 4. Filtrar falsos positivos evidentes
            flows = self._filter_obvious_false_positives(flows)
            self.logger.info(f"Después de filtrado: {len(flows)} flujos")
            
            # 5. Generar grafos etiquetados de alto nivel
            flows = self._enhance_with_labeled_graphs(flows, data_flow_graph)
            
            return flows
            
        except Exception as e:
            self.logger.error(f"Error en análisis taint: {str(e)}", exc_info=True)
            return []
    
    def _load_sources(self, source_patterns: List[str]) -> Set[str]:
        """Carga definiciones de sources críticos Android"""
        sources = set()
        
        # Sources predefinidos críticos
        default_sources = [
            # Ubicación
            "android.location.LocationManager: android.location.Location getLastKnownLocation(*)",
            "com.google.android.gms.location.FusedLocationProviderClient: * getLastLocation()",
            
            # Identificadores
            "android.telephony.TelephonyManager: java.lang.String getDeviceId()",
            "android.telephony.TelephonyManager: java.lang.String getSubscriberId()",
            "android.provider.Settings$Secure: java.lang.String getString(*, java.lang.String)",
            
            # Contactos
            "android.provider.ContactsContract$CommonDataKinds$Phone: android.net.Uri CONTENT_URI",
            "android.content.ContentResolver: android.database.Cursor query(*)",
            
            # Sensores biométricos
            "android.hardware.fingerprint.FingerprintManager: void authenticate(*)",
            
            # Cámara/Micrófono
            "android.hardware.Camera: void takePicture(*)",
            "android.media.MediaRecorder: void start()",
            
            # Storage sensible
            "android.content.SharedPreferences: * get*(java.lang.String, *)",
            "java.io.FileInputStream: <init>(java.io.File)",
        ]
        
        sources.update(default_sources)
        sources.update(source_patterns)
        
        return sources
    
    def _load_sinks(self, sink_patterns: List[str]) -> Set[str]:
        """Carga definiciones de sinks peligrosos Android"""
        sinks = set()
        
        # Sinks predefinidos peligrosos
        default_sinks = [
            # Comunicación de red
            "java.net.HttpURLConnection: void connect()",
            "java.net.URL: java.net.URLConnection openConnection()",
            "okhttp3.OkHttpClient: okhttp3.Call newCall(okhttp3.Request)",
            "okhttp3.Request$Builder: okhttp3.Request build()",
            
            # WebView
            "android.webkit.WebView: void loadUrl(java.lang.String)",
            "android.webkit.WebView: void loadData(java.lang.String, *, *)",
            
            # Logging
            "android.util.Log: int d(java.lang.String, java.lang.String)",
            "android.util.Log: int e(java.lang.String, java.lang.String)",
            "android.util.Log: int i(java.lang.String, java.lang.String)",
            
            # Intent communication
            "android.content.Intent: android.content.Intent putExtra(java.lang.String, *)",
            "android.content.Context: void sendBroadcast(android.content.Intent)",
            "android.content.Context: void startActivity(android.content.Intent)",
            
            # Storage externo
            "java.io.FileOutputStream: <init>(java.io.File)",
            "java.io.FileWriter: <init>(java.lang.String)",
        ]
        
        sinks.update(default_sinks)
        sinks.update(sink_patterns)
        
        return sinks
    
    def _identify_entry_points(
        self,
        manifest: Dict[str, Any],
        cfg: Dict[str, Any]
    ) -> List[str]:
        """
        Identifica puntos de entrada de la aplicación
        - Lifecycle callbacks
        - Componentes exportados
        - Intent handlers
        """
        entry_points = []
        
        # Activities
        for activity in manifest.get('activities', []):
            entry_points.extend([
                f"{activity}.onCreate",
                f"{activity}.onStart",
                f"{activity}.onResume"
            ])
        
        # Services
        for service in manifest.get('services', []):
            entry_points.extend([
                f"{service}.onCreate",
                f"{service}.onStartCommand"
            ])
        
        # BroadcastReceivers
        for receiver in manifest.get('receivers', []):
            entry_points.append(f"{receiver}.onReceive")
        
        return entry_points
    
    def _build_data_flow_graph(
        self,
        jimple_code: Dict[str, Any],
        cfg: Dict[str, Any]
    ) -> nx.DiGraph:
        """
        Construye grafo de flujo de datos desde código Jimple
        
        Returns:
            NetworkX DiGraph con flujos de datos
        """
        G = nx.DiGraph()
        
        # En implementación real:
        # 1. Parsear statements Jimple
        # 2. Identificar def-use chains
        # 3. Construir aristas de flujo de datos
        # 4. Considerar llamadas a métodos
        
        # Simulación para demostración
        self.logger.warning("Construcción de data flow graph simulada")
        
        return G
    
    def _find_paths(
        self,
        source: str,
        sink: str,
        graph: nx.DiGraph
    ) -> List[List[str]]:
        """
        Encuentra todos los caminos desde source hasta sink
        
        Returns:
            Lista de caminos (cada camino es lista de nodos)
        """
        paths = []
        
        try:
            # Usar algoritmo de búsqueda de caminos en NetworkX
            if graph.has_node(source) and graph.has_node(sink):
                all_paths = nx.all_simple_paths(
                    graph,
                    source,
                    sink,
                    cutoff=self.max_depth
                )
                paths = list(all_paths)
        except nx.NetworkXNoPath:
            pass
        
        return paths
    
    def _create_taint_flow(
        self,
        source: str,
        sink: str,
        path: List[str],
        manifest: Dict[str, Any],
        jimple_code: Dict[str, Any]
    ) -> TaintFlow:
        """
        Crea objeto TaintFlow con metadata completa
        """
        # Extraer secuencia de APIs del path
        api_sequence = self._extract_api_sequence(path)
        
        # Determinar permisos involucrados
        permissions = self._extract_permissions(source, sink, manifest)
        
        # Identificar componentes Android involucrados
        components = self._extract_components(path)
        
        # Calcular criticidad inicial (heurística)
        criticality = self._calculate_initial_criticality(
            source, sink, permissions, components
        )
        
        flow = TaintFlow(
            source=source,
            sink=sink,
            path=path,
            api_sequence=api_sequence,
            permissions=permissions,
            components=components,
            criticality_score=criticality,
            metadata={
                'path_length': len(path),
                'has_reflection': self._contains_reflection(api_sequence),
                'has_encryption': self._contains_encryption(api_sequence),
                'inter_component': len(components) > 1
            }
        )
        
        return flow
    
    def _extract_api_sequence(self, path: List[str]) -> List[str]:
        """Extrae secuencia de llamadas a APIs desde el path"""
        # Filtrar solo métodos que sean APIs relevantes
        api_sequence = []
        for node in path:
            if '.' in node and ':' in node:
                api_sequence.append(node)
        return api_sequence
    
    def _extract_permissions(
        self,
        source: str,
        sink: str,
        manifest: Dict[str, Any]
    ) -> List[str]:
        """Determina permisos Android necesarios para el flujo"""
        permissions = []
        all_perms = manifest.get('permissions', [])
        
        # Mapeo simple source/sink -> permisos
        if 'Location' in source:
            permissions.extend([p for p in all_perms if 'LOCATION' in p])
        if 'TelephonyManager' in source:
            permissions.extend([p for p in all_perms if 'PHONE' in p])
        if 'Camera' in source:
            permissions.extend([p for p in all_perms if 'CAMERA' in p])
        if 'HttpURLConnection' in sink or 'OkHttp' in sink:
            permissions.extend([p for p in all_perms if 'INTERNET' in p])
        
        return list(set(permissions))
    
    def _extract_components(self, path: List[str]) -> List[str]:
        """Identifica componentes Android en el path"""
        components = set()
        
        # Detectar componentes comunes en el path
        component_keywords = ['Activity', 'Service', 'Receiver', 'Provider']
        
        for node in path:
            for keyword in component_keywords:
                if keyword in node:
                    components.add(node.split('.')[0])
        
        return list(components)
    
    def _calculate_initial_criticality(
        self,
        source: str,
        sink: str,
        permissions: List[str],
        components: List[str]
    ) -> float:
        """
        Calcula criticidad inicial heurística del flujo
        
        Returns:
            Score [0, 1]
        """
        score = 0.5  # Base
        
        # Aumentar por source sensitivo
        sensitive_sources = ['Location', 'DeviceId', 'Contact', 'Camera']
        if any(s in source for s in sensitive_sources):
            score += 0.2
        
        # Aumentar por sink peligroso
        dangerous_sinks = ['HttpURLConnection', 'OkHttp', 'WebView', 'Log']
        if any(s in sink for s in dangerous_sinks):
            score += 0.2
        
        # Aumentar por permisos peligrosos
        if len(permissions) > 0:
            score += 0.1 * min(len(permissions), 3)
        
        # Disminuir si hay cifrado
        # (será refinado por Transformer)
        
        return min(score, 1.0)
    
    def _contains_reflection(self, api_sequence: List[str]) -> bool:
        """Detecta uso de reflexión en el flujo"""
        reflection_keywords = ['reflect.Method', 'reflect.Field', 'reflect.Constructor']
        return any(keyword in api for api in api_sequence for keyword in reflection_keywords)
    
    def _contains_encryption(self, api_sequence: List[str]) -> bool:
        """Detecta uso de criptografía en el flujo"""
        crypto_keywords = ['javax.crypto', 'Cipher', 'MessageDigest', 'SecretKey']
        return any(keyword in api for api in api_sequence for keyword in crypto_keywords)
    
    def _filter_obvious_false_positives(self, flows: List[TaintFlow]) -> List[TaintFlow]:
        """
        Filtra falsos positivos obvios usando heurísticas
        """
        filtered = []
        
        for flow in flows:
            # Permitir flujos con cifrado (probablemente legítimos)
            if flow.metadata.get('has_encryption', False):
                flow.criticality_score *= 0.5  # Reducir score
            
            # Filtrar logging en modo debug
            if 'Log.d' in flow.sink and 'debug' in ' '.join(flow.api_sequence).lower():
                continue
            
            # Mantener todos los demás para análisis Transformer
            filtered.append(flow)
        
        return filtered
    
    def _enhance_with_labeled_graphs(
        self,
        flows: List[TaintFlow],
        dfg: nx.DiGraph
    ) -> List[TaintFlow]:
        """
        Mejora flujos con grafos etiquetados de Li et al.
        """
        for flow in flows:
            # Crear subgrafo etiquetado para este flujo
            labeled_graph = self._create_labeled_subgraph(flow.path, dfg)
            flow.metadata['labeled_graph'] = labeled_graph
        
        return flows
    
    def _create_labeled_subgraph(self, path: List[str], dfg: nx.DiGraph) -> Dict:
        """
        Crea grafo etiquetado con semántica contextual
        """
        subgraph = {
            'nodes': [],
            'edges': [],
            'labels': {}
        }
        
        # Etiquetar nodos según tipo de operación
        for node in path:
            node_type = self._classify_node_type(node)
            subgraph['nodes'].append({
                'id': node,
                'type': node_type,
                'criticality': self._get_node_criticality(node, node_type)
            })
        
        # Etiquetar aristas según tipo de flujo
        for i in range(len(path) - 1):
            edge_type = self._classify_edge_type(path[i], path[i+1])
            subgraph['edges'].append({
                'from': path[i],
                'to': path[i+1],
                'type': edge_type
            })
        
        return subgraph
    
    def _classify_node_type(self, node: str) -> str:
        """Clasifica tipo de nodo en el grafo"""
        if any(s in node for s in ['Location', 'Contact', 'DeviceId']):
            return 'SOURCE'
        elif any(s in node for s in ['HttpURLConnection', 'OkHttp', 'WebView']):
            return 'SINK'
        elif 'crypto' in node.lower() or 'Cipher' in node:
            return 'TRANSFORM'
        else:
            return 'INTERMEDIATE'
    
    def _get_node_criticality(self, node: str, node_type: str) -> str:
        """Determina criticidad del nodo"""
        if node_type == 'SOURCE':
            return 'HIGH' if any(k in node for k in ['Location', 'DeviceId']) else 'MEDIUM'
        elif node_type == 'SINK':
            return 'HIGH' if 'Http' in node else 'MEDIUM'
        else:
            return 'LOW'
    
    def _classify_edge_type(self, from_node: str, to_node: str) -> str:
        """Clasifica tipo de arista"""
        if 'Intent' in from_node or 'Intent' in to_node:
            return 'INTER_COMPONENT'
        elif 'crypto' in from_node.lower() or 'crypto' in to_node.lower():
            return 'ENCRYPTED'
        else:
            return 'DIRECT'

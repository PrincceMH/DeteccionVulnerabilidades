"""
MÓDULO 1: Preprocesamiento APK
Responsable de descompilación, conversión a Jimple, y extracción de metadatos
"""

import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any
import shutil
import tempfile
import logging


class APKPreprocessor:
    """
    Preprocesa APKs para análisis posterior
    - Descompilación con Jadx
    - Conversión a Jimple con Soot
    - Extracción de AndroidManifest
    - Generación de CFGs
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: Configuración del módulo de preprocesamiento
        """
        self.config = config
        self.logger = logging.getLogger("APKPreprocessor")
        self.jadx_path = config.get('jadx', {}).get('path', 'jadx')
        self.android_jars = config.get('soot', {}).get('android_jars', 'android-platforms/')
        self.quality_threshold = config.get('quality_threshold', 0.7)
    
    def process(self, apk_path: str) -> Dict[str, Any]:
        """
        Procesa una APK completamente
        
        Args:
            apk_path: Ruta al archivo APK
            
        Returns:
            Diccionario con todos los datos preprocesados
        """
        self.logger.info(f"Preprocesando APK: {apk_path}")
        
        # Crear directorio temporal
        temp_dir = tempfile.mkdtemp(prefix="apk_preprocess_")
        
        try:
            results = {
                'apk_path': apk_path,
                'apk_name': Path(apk_path).stem,
                'temp_dir': temp_dir
            }
            
            # 1. Descompilación con Jadx
            self.logger.info("Descompilando con Jadx...")
            java_code_dir = self._decompile_with_jadx(apk_path, temp_dir)
            results['java_code_dir'] = java_code_dir
            results['decompilation_quality'] = self._assess_decompilation_quality(java_code_dir)
            
            # 2. Extracción de AndroidManifest.xml
            self.logger.info("Extrayendo AndroidManifest.xml...")
            manifest_data = self._extract_manifest(apk_path, temp_dir)
            results['manifest'] = manifest_data
            
            # 3. Conversión a Jimple con Soot
            self.logger.info("Convirtiendo a representación Jimple...")
            jimple_code = self._convert_to_jimple(apk_path, temp_dir)
            results['jimple_code'] = jimple_code
            
            # 4. Generación de CFGs
            self.logger.info("Generando grafos de flujo de control...")
            cfg = self._generate_cfg(jimple_code)
            results['cfg'] = cfg
            
            # 5. Extracción de metadatos
            self.logger.info("Extrayendo metadatos estructurales...")
            metadata = self._extract_metadata(manifest_data, jimple_code)
            results['metadata'] = metadata
            
            self.logger.info("Preprocesamiento completado exitosamente")
            return results
            
        except Exception as e:
            self.logger.error(f"Error en preprocesamiento: {str(e)}", exc_info=True)
            raise
        finally:
            # Limpiar directorio temporal (opcional, comentar para debug)
            # shutil.rmtree(temp_dir, ignore_errors=True)
            pass
    
    def _decompile_with_jadx(self, apk_path: str, output_dir: str) -> str:
        """
        Descompila APK usando Jadx
        
        Returns:
            Ruta al directorio con código Java decompilado
        """
        java_output = Path(output_dir) / "java_code"
        java_output.mkdir(exist_ok=True)
        
        # Comando Jadx
        cmd = [
            self.jadx_path,
            apk_path,
            "-d", str(java_output),
            "--no-res",  # No descompilar recursos
        ]
        
        if self.config.get('jadx', {}).get('deobfuscate', True):
            cmd.append("--deobf")
        
        threads = self.config.get('jadx', {}).get('threads', 4)
        cmd.extend(["-j", str(threads)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                self.logger.warning(f"Jadx finalizó con warnings: {result.stderr}")
            
            return str(java_output)
            
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout en descompilación con Jadx")
            raise
        except FileNotFoundError:
            self.logger.error(f"Jadx no encontrado en: {self.jadx_path}")
            raise
    
    def _extract_manifest(self, apk_path: str, output_dir: str) -> Dict[str, Any]:
        """
        Extrae y parsea AndroidManifest.xml
        
        Returns:
            Diccionario con datos del manifest
        """
        manifest_path = Path(output_dir) / "AndroidManifest.xml"
        
        # Extraer manifest usando apktool o aapt
        # Por simplicidad, usamos androguard (si está disponible)
        try:
            from androguard.core.bytecodes.apk import APK
            
            apk = APK(apk_path)
            
            manifest_data = {
                'package': apk.get_package(),
                'version_code': apk.get_androidversion_code(),
                'version_name': apk.get_androidversion_name(),
                'min_sdk': apk.get_min_sdk_version(),
                'target_sdk': apk.get_target_sdk_version(),
                'permissions': apk.get_permissions(),
                'activities': apk.get_activities(),
                'services': apk.get_services(),
                'receivers': apk.get_receivers(),
                'providers': apk.get_providers(),
                'main_activity': apk.get_main_activity()
            }
            
            # Clasificar permisos por criticidad
            manifest_data['dangerous_permissions'] = self._classify_permissions(
                apk.get_permissions()
            )
            
            # Identificar componentes exportados
            manifest_data['exported_components'] = self._identify_exported_components(apk)
            
            return manifest_data
            
        except ImportError:
            self.logger.warning("Androguard no disponible, extracción limitada")
            return {'package': 'unknown', 'permissions': []}
    
    def _convert_to_jimple(self, apk_path: str, output_dir: str) -> Dict[str, List[str]]:
        """
        Convierte APK a representación intermedia Jimple usando Soot
        
        Returns:
            Diccionario con código Jimple por clase
        """
        jimple_output = Path(output_dir) / "jimple"
        jimple_output.mkdir(exist_ok=True)
        
        # Nota: Aquí se requiere integración con Soot (Java)
        # Por simplicidad, simulamos la estructura esperada
        
        # En implementación real:
        # 1. Ejecutar Soot via subprocess con JVM
        # 2. Parsear archivos .jimple generados
        # 3. Retornar estructura de datos
        
        self.logger.warning("Conversión Jimple simulada (requiere Soot Framework)")
        
        jimple_code = {
            'classes': [],
            'methods': [],
            'call_graph': {},
            'jimple_files': []
        }
        
        return jimple_code
    
    def _generate_cfg(self, jimple_code: Dict) -> Dict[str, Any]:
        """
        Genera grafos de flujo de control (CFG) desde código Jimple
        
        Returns:
            Diccionario con CFGs por método
        """
        cfg = {
            'methods': {},
            'entry_points': [],
            'lifecycle_aware': True
        }
        
        # Implementación real requiere análisis con Soot
        self.logger.warning("Generación CFG simulada")
        
        return cfg
    
    def _extract_metadata(self, manifest: Dict, jimple: Dict) -> Dict[str, Any]:
        """
        Extrae metadatos estructurales de la aplicación
        """
        metadata = {
            'package_name': manifest.get('package', 'unknown'),
            'total_permissions': len(manifest.get('permissions', [])),
            'dangerous_permissions': len(manifest.get('dangerous_permissions', [])),
            'total_components': (
                len(manifest.get('activities', [])) +
                len(manifest.get('services', [])) +
                len(manifest.get('receivers', [])) +
                len(manifest.get('providers', []))
            ),
            'exported_components': len(manifest.get('exported_components', [])),
            'total_classes': len(jimple.get('classes', [])),
            'total_methods': len(jimple.get('methods', []))
        }
        
        return metadata
    
    def _assess_decompilation_quality(self, java_code_dir: str) -> float:
        """
        Evalúa calidad de descompilación
        
        Returns:
            Score de calidad [0, 1]
        """
        java_path = Path(java_code_dir)
        
        if not java_path.exists():
            return 0.0
        
        # Métricas simples de calidad
        java_files = list(java_path.rglob("*.java"))
        
        if not java_files:
            return 0.0
        
        # Calcular proporción de archivos válidos
        valid_files = 0
        for java_file in java_files[:100]:  # Muestrear primeros 100
            try:
                content = java_file.read_text(encoding='utf-8', errors='ignore')
                # Heurística: archivo válido debe tener estructura básica
                if 'class ' in content or 'interface ' in content:
                    valid_files += 1
            except:
                continue
        
        quality = valid_files / min(len(java_files), 100)
        return quality
    
    def _classify_permissions(self, permissions: List[str]) -> List[Dict[str, str]]:
        """
        Clasifica permisos según nivel de peligrosidad OWASP
        """
        dangerous_keywords = [
            'CAMERA', 'LOCATION', 'CONTACTS', 'SMS', 'PHONE',
            'MICROPHONE', 'STORAGE', 'CALENDAR', 'BODY_SENSORS'
        ]
        
        dangerous = []
        for perm in permissions:
            for keyword in dangerous_keywords:
                if keyword in perm.upper():
                    dangerous.append({
                        'permission': perm,
                        'category': keyword,
                        'criticality': 'HIGH'
                    })
                    break
        
        return dangerous
    
    def _identify_exported_components(self, apk) -> List[Dict[str, str]]:
        """
        Identifica componentes exportados sin protección adecuada
        """
        # Requiere análisis más profundo del manifest XML
        # Por ahora retornamos estructura vacía
        exported = []
        
        return exported

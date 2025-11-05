"""
MÓDULO 4: Validación Dinámica Selectiva con Frida
Confirma vulnerabilidades críticas mediante instrumentación
"""

import logging
import json
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
import subprocess
import base64
import hashlib


class FridaValidator:
    """
    Validador dinámico que usa Frida para confirmar vulnerabilidades
    - Instrumentación no intrusiva
    - Taint propagation testing
    - Permission bypass validation
    - Communication security testing
    - Generación automática de PoCs
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: Configuración del módulo de validación dinámica
        """
        self.config = config
        self.logger = logging.getLogger("FridaValidator")
        
        # Configuración Frida
        self.frida_timeout = config.get('frida', {}).get('timeout_seconds', 60)
        self.script_path = Path(config.get('frida', {}).get('script_path', 'frida_scripts/'))
        
        # Configuración emulador
        self.emulator_config = config.get('emulator', {})
        self.api_level = self.emulator_config.get('api_level', 30)
        
        # Estrategia de activación
        self.activation_threshold = config.get('activation', {}).get('score_threshold', 0.75)
        self.max_validations = config.get('activation', {}).get('max_validations_per_apk', 10)
        
        # Técnicas de testing
        self.techniques = config.get('techniques', {})
        
        self.logger.info("Validador dinámico inicializado")
    
    def validate(self, apk_path: str, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Valida una vulnerabilidad mediante análisis dinámico
        
        Args:
            apk_path: Ruta al APK a validar
            vulnerability: Dict con info de vulnerabilidad del Transformer
            
        Returns:
            Resultado de validación con evidencia
        """
        self.logger.info(f"Validando vulnerabilidad (score: {vulnerability['score']:.3f})...")
        
        validation_result = {
            'validated': False,
            'exploitable': False,
            'confidence': 0.0,
            'evidence': [],
            'poc': None,
            'timestamp': time.time()
        }
        
        try:
            flow = vulnerability['flow']
            
            # 1. Iniciar emulador y instalar APK
            device_id = self._setup_environment(apk_path)
            
            if not device_id:
                self.logger.error("No se pudo configurar entorno de validación")
                return validation_result
            
            # 2. Aplicar técnicas de validación según tipo de vulnerabilidad
            if self.techniques.get('taint_propagation', True):
                taint_result = self._validate_taint_propagation(
                    device_id, apk_path, flow
                )
                validation_result['evidence'].append(taint_result)
                
                if taint_result.get('confirmed', False):
                    validation_result['validated'] = True
                    validation_result['exploitable'] = True
            
            if self.techniques.get('permission_bypass', True):
                perm_result = self._validate_permission_bypass(
                    device_id, apk_path, flow
                )
                validation_result['evidence'].append(perm_result)
            
            if self.techniques.get('communication_security', True):
                comm_result = self._validate_communication_security(
                    device_id, apk_path, flow
                )
                validation_result['evidence'].append(comm_result)
            
            # 3. Calcular confianza de validación
            validation_result['confidence'] = self._calculate_confidence(
                validation_result['evidence']
            )
            
            # 4. Generar PoC si está confirmada
            if validation_result['exploitable'] and self.techniques.get('generate_poc', True):
                poc = self._generate_poc(apk_path, flow, validation_result['evidence'])
                validation_result['poc'] = poc
            
            # 5. Limpiar entorno
            self._cleanup_environment(device_id)
            
            self.logger.info(f"Validación completada. Explotable: {validation_result['exploitable']}")
            return validation_result
            
        except Exception as e:
            self.logger.error(f"Error en validación: {str(e)}", exc_info=True)
            validation_result['error'] = str(e)
            return validation_result
    
    def _setup_environment(self, apk_path: str) -> Optional[str]:
        """
        Configura entorno de testing (emulador + APK instalada)
        
        Returns:
            ID del dispositivo/emulador o None si falla
        """
        self.logger.info("Configurando entorno de validación...")
        
        try:
            # 1. Verificar si hay emulador disponible
            result = subprocess.run(
                ['adb', 'devices'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            devices = self._parse_adb_devices(result.stdout)
            
            if not devices:
                self.logger.warning("No hay dispositivos Android disponibles")
                # En producción: iniciar emulador automáticamente
                return None
            
            device_id = devices[0]
            self.logger.info(f"Usando dispositivo: {device_id}")
            
            # 2. Instalar APK
            self._install_apk(device_id, apk_path)
            
            # 3. Iniciar Frida server en dispositivo
            self._start_frida_server(device_id)
            
            return device_id
            
        except Exception as e:
            self.logger.error(f"Error configurando entorno: {str(e)}")
            return None
    
    def _validate_taint_propagation(
        self,
        device_id: str,
        apk_path: str,
        flow: Any
    ) -> Dict[str, Any]:
        """
        Valida propagación de taint mediante instrumentación
        
        Técnica:
        1. Inyectar marcador único en source
        2. Monitorear sink para detectar marcador
        3. Confirmar propagación real
        """
        self.logger.info("Validando propagación de taint...")
        
        result = {
            'technique': 'taint_propagation',
            'confirmed': False,
            'marker_injected': False,
            'marker_detected': False,
            'propagation_trace': []
        }
        
        try:
            # 1. Generar marcador único
            marker = self._generate_taint_marker()
            result['marker'] = marker
            
            # 2. Preparar script Frida
            frida_script = self._create_taint_script(flow, marker)
            
            # 3. Ejecutar instrumentación
            package_name = self._get_package_name(apk_path)
            
            # Iniciar app
            self._launch_app(device_id, package_name)
            time.sleep(2)
            
            # Inyectar script Frida
            output = self._inject_frida_script(device_id, package_name, frida_script)
            
            # 4. Analizar resultados
            if marker in output:
                result['confirmed'] = True
                result['marker_detected'] = True
                result['propagation_trace'] = self._extract_trace(output)
                self.logger.info("✓ Propagación de taint confirmada")
            else:
                self.logger.info("✗ No se detectó propagación de taint")
            
        except Exception as e:
            self.logger.error(f"Error en validación taint: {str(e)}")
            result['error'] = str(e)
        
        return result
    
    def _validate_permission_bypass(
        self,
        device_id: str,
        apk_path: str,
        flow: Any
    ) -> Dict[str, Any]:
        """
        Valida si hay bypass de permisos Android
        """
        self.logger.info("Validando bypass de permisos...")
        
        result = {
            'technique': 'permission_bypass',
            'confirmed': False,
            'permissions_required': flow.permissions,
            'bypassed_permissions': []
        }
        
        # Implementación simplificada
        # En producción: verificar acceso sin permisos declarados
        
        return result
    
    def _validate_communication_security(
        self,
        device_id: str,
        apk_path: str,
        flow: Any
    ) -> Dict[str, Any]:
        """
        Valida seguridad de comunicaciones (HTTPS, cert pinning, etc.)
        """
        self.logger.info("Validando seguridad de comunicación...")
        
        result = {
            'technique': 'communication_security',
            'confirmed': False,
            'uses_https': False,
            'validates_certificates': False,
            'data_transmitted': []
        }
        
        # Implementación simplificada
        # En producción: interceptar tráfico de red con mitmproxy
        
        return result
    
    def _generate_poc(
        self,
        apk_path: str,
        flow: Any,
        evidence: List[Dict]
    ) -> Dict[str, Any]:
        """
        Genera Proof of Concept automatizado
        
        Returns:
            Dict con script PoC y documentación
        """
        self.logger.info("Generando PoC...")
        
        package_name = self._get_package_name(apk_path)
        
        poc = {
            'title': f"PoC: Vulnerabilidad en {package_name}",
            'description': f"Flujo vulnerable: {flow.source} → {flow.sink}",
            'severity': 'CRITICAL',
            'steps': [],
            'script': None,
            'evidence_files': []
        }
        
        # Generar script de explotación
        exploit_script = self._create_exploit_script(flow, evidence)
        poc['script'] = exploit_script
        
        # Pasos de reproducción
        poc['steps'] = [
            f"1. Instalar APK: adb install {Path(apk_path).name}",
            f"2. Iniciar app: adb shell am start -n {package_name}/.MainActivity",
            "3. Ejecutar script de explotación:",
            f"   python exploit.py {package_name}",
            "4. Verificar exfiltración de datos en logs"
        ]
        
        return poc
    
    def _create_exploit_script(self, flow: Any, evidence: List[Dict]) -> str:
        """Genera script Python de explotación"""
        
        script = f"""#!/usr/bin/env python3
\"\"\"
Proof of Concept - Vulnerabilidad de Exfiltración de Datos
Generado automáticamente por Framework de Detección

Flujo vulnerable:
  Source: {flow.source}
  Sink: {flow.sink}
  
Descripción:
  La aplicación expone datos sensibles sin protección adecuada.
\"\"\"

import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {{message['payload']}}")
    else:
        print(message)

def exploit(package_name):
    print(f"[+] Adjuntando a proceso: {{package_name}}")
    
    device = frida.get_usb_device()
    session = device.attach(package_name)
    
    script_code = \"\"\"
    Java.perform(function() {{
        // Hook source
        var SourceClass = Java.use('{flow.source.split(':')[0]}');
        SourceClass.{flow.source.split('.')[-1]}.implementation = function() {{
            console.log("[*] Source invocada - datos sensibles accedidos");
            var result = this.{flow.source.split('.')[-1]}.apply(this, arguments);
            console.log("[*] Datos obtenidos: " + result);
            return result;
        }};
        
        // Hook sink
        var SinkClass = Java.use('{flow.sink.split(':')[0]}');
        SinkClass.{flow.sink.split('.')[-1]}.implementation = function() {{
            console.log("[!] Sink invocado - posible exfiltración");
            console.log("[!] Datos enviados: " + arguments[0]);
            return this.{flow.sink.split('.')[-1]}.apply(this, arguments);
        }};
    }});
    \"\"\"
    
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    
    print("[+] Script cargado. Monitoreando flujo de datos...")
    print("[*] Presiona Ctrl+C para detener")
    
    sys.stdin.read()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Uso: {{sys.argv[0]}} <package_name>")
        sys.exit(1)
    
    exploit(sys.argv[1])
"""
        
        return script
    
    def _generate_taint_marker(self) -> str:
        """Genera marcador único para tracking de taint"""
        config = self.config.get('markers', {})
        prefix = config.get('prefix', 'TAINT_MARKER_')
        length = config.get('length', 32)
        
        # Generar hash único
        unique = hashlib.sha256(str(time.time()).encode()).hexdigest()[:length]
        marker = f"{prefix}{unique}"
        
        return marker
    
    def _create_taint_script(self, flow: Any, marker: str) -> str:
        """Crea script Frida para tracking de taint"""
        
        script = f"""
Java.perform(function() {{
    var marker = "{marker}";
    
    // Hook source para inyectar marcador
    try {{
        var SourceClass = Java.use('{flow.source.split(':')[0]}');
        SourceClass.{flow.source.split('.')[-1]}.implementation = function() {{
            console.log("[TAINT] Inyectando marcador en source");
            return marker;  // Retornar marcador en lugar de valor real
        }};
    }} catch(e) {{
        console.log("[ERROR] No se pudo hookear source: " + e);
    }}
    
    // Hook sink para detectar marcador
    try {{
        var SinkClass = Java.use('{flow.sink.split(':')[0]}');
        SinkClass.{flow.sink.split('.')[-1]}.implementation = function() {{
            var args = Array.prototype.slice.call(arguments);
            var argsStr = JSON.stringify(args);
            
            if (argsStr.indexOf(marker) !== -1) {{
                console.log("[TAINT] ¡Marcador detectado en sink!");
                console.log("[TAINT] Propagación confirmada");
                console.log("[TAINT] Datos: " + argsStr);
            }}
            
            return this.{flow.sink.split('.')[-1]}.apply(this, arguments);
        }};
    }} catch(e) {{
        console.log("[ERROR] No se pudo hookear sink: " + e);
    }}
}});
"""
        return script
    
    def _inject_frida_script(
        self,
        device_id: str,
        package_name: str,
        script_code: str
    ) -> str:
        """Inyecta script Frida en proceso de la app"""
        
        # Guardar script temporalmente
        script_file = Path("/tmp/frida_script.js")
        script_file.write_text(script_code)
        
        try:
            # Ejecutar frida
            cmd = [
                'frida',
                '-U',  # USB device
                '-f', package_name,  # Spawn
                '-l', str(script_file),
                '--no-pause'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.frida_timeout
            )
            
            return result.stdout + result.stderr
            
        except subprocess.TimeoutExpired as e:
            return e.stdout.decode() if e.stdout else ""
    
    def _calculate_confidence(self, evidence: List[Dict]) -> float:
        """Calcula confianza de validación basado en evidencia"""
        if not evidence:
            return 0.0
        
        confirmed = sum(1 for e in evidence if e.get('confirmed', False))
        confidence = confirmed / len(evidence)
        
        return confidence
    
    def _parse_adb_devices(self, output: str) -> List[str]:
        """Parsea output de 'adb devices'"""
        devices = []
        for line in output.split('\n')[1:]:  # Skip header
            if '\t' in line:
                device_id = line.split('\t')[0]
                devices.append(device_id)
        return devices
    
    def _install_apk(self, device_id: str, apk_path: str) -> bool:
        """Instala APK en dispositivo"""
        try:
            cmd = ['adb', '-s', device_id, 'install', '-r', apk_path]
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            return result.returncode == 0
        except:
            return False
    
    def _start_frida_server(self, device_id: str) -> bool:
        """Inicia Frida server en dispositivo"""
        try:
            # Verificar si frida-server está corriendo
            cmd = ['adb', '-s', device_id, 'shell', 'pidof', 'frida-server']
            result = subprocess.run(cmd, capture_output=True)
            
            if result.returncode != 0:
                # Iniciar frida-server
                subprocess.Popen(
                    ['adb', '-s', device_id, 'shell', '/data/local/tmp/frida-server', '&']
                )
                time.sleep(2)
            
            return True
        except:
            return False
    
    def _get_package_name(self, apk_path: str) -> str:
        """Extrae package name de APK"""
        try:
            from androguard.core.bytecodes.apk import APK
            apk = APK(apk_path)
            return apk.get_package()
        except:
            return "com.example.app"
    
    def _launch_app(self, device_id: str, package_name: str) -> bool:
        """Lanza aplicación en dispositivo"""
        try:
            cmd = [
                'adb', '-s', device_id, 'shell', 'monkey',
                '-p', package_name,
                '-c', 'android.intent.category.LAUNCHER', '1'
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def _extract_trace(self, output: str) -> List[str]:
        """Extrae trace de propagación desde output de Frida"""
        trace = []
        for line in output.split('\n'):
            if '[TAINT]' in line:
                trace.append(line.strip())
        return trace
    
    def _cleanup_environment(self, device_id: str) -> None:
        """Limpia entorno de testing"""
        self.logger.info("Limpiando entorno...")
        # Implementar: desinstalar app, detener procesos, etc.

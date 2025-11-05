"""
Framework principal para detección de vulnerabilidades Android
Integra los 4 módulos: Preprocesamiento, Taint Analysis, Transformer, Validación Dinámica
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

from modules.preprocessing.apk_preprocessor import APKPreprocessor
from modules.taint_analysis.taint_analyzer import TaintAnalyzer
from modules.transformer_model.vulnerability_classifier import VulnerabilityClassifier
from modules.dynamic_validation.frida_validator import FridaValidator
from utils.logger import setup_logger
from utils.config_loader import load_config
from utils.report_generator import ReportGenerator


class VulnerabilityDetectionFramework:
    """
    Framework principal que coordina los 4 módulos del sistema
    """
    
    def __init__(self, config_path: str = "config/default_config.yaml"):
        """
        Inicializa el framework con configuración
        
        Args:
            config_path: Ruta al archivo de configuración YAML
        """
        self.config = load_config(config_path)
        self.logger = setup_logger("Framework", self.config['logging']['level'])
        
        # Inicializar módulos
        self.logger.info("Inicializando módulos del framework...")
        self.preprocessor = APKPreprocessor(self.config['preprocessing'])
        self.taint_analyzer = TaintAnalyzer(self.config['taint_analysis'])
        self.classifier = VulnerabilityClassifier(self.config['transformer'])
        self.validator = FridaValidator(self.config['dynamic_validation'])
        
        self.logger.info("Framework inicializado correctamente")
    
    def analyze_apk(self, apk_path: str, output_dir: str = "results/") -> Dict:
        """
        Analiza una APK completa a través de todos los módulos
        
        Args:
            apk_path: Ruta al archivo APK
            output_dir: Directorio para guardar resultados
            
        Returns:
            Diccionario con resultados del análisis
        """
        self.logger.info(f"Iniciando análisis de: {apk_path}")
        results = {
            'apk_path': apk_path,
            'preprocessing': {},
            'taint_flows': [],
            'vulnerabilities': [],
            'validated': []
        }
        
        try:
            # MÓDULO 1: Preprocesamiento
            self.logger.info("Módulo 1: Preprocesamiento APK...")
            preprocessing_data = self.preprocessor.process(apk_path)
            results['preprocessing'] = preprocessing_data
            
            # MÓDULO 2: Análisis Taint
            self.logger.info("Módulo 2: Análisis de flujos taint...")
            taint_flows = self.taint_analyzer.analyze(
                preprocessing_data['jimple_code'],
                preprocessing_data['manifest'],
                preprocessing_data['cfg']
            )
            results['taint_flows'] = taint_flows
            self.logger.info(f"Detectados {len(taint_flows)} flujos potenciales")
            
            # MÓDULO 3: Clasificación con Transformer
            self.logger.info("Módulo 3: Clasificación con modelo Transformer...")
            vulnerabilities = []
            for flow in taint_flows:
                score = self.classifier.classify_flow(flow)
                if score >= self.config['transformer']['threshold_low']:
                    vulnerabilities.append({
                        'flow': flow,
                        'score': score,
                        'criticality': self._get_criticality(score)
                    })
            results['vulnerabilities'] = vulnerabilities
            self.logger.info(f"Identificadas {len(vulnerabilities)} vulnerabilidades potenciales")
            
            # MÓDULO 4: Validación Dinámica Selectiva
            self.logger.info("Módulo 4: Validación dinámica selectiva...")
            validated = []
            critical_threshold = self.config['transformer']['threshold_critical']
            
            for vuln in vulnerabilities:
                if vuln['score'] >= critical_threshold:
                    self.logger.info(f"Validando vulnerabilidad crítica (score: {vuln['score']:.3f})...")
                    validation_result = self.validator.validate(apk_path, vuln)
                    vuln['validated'] = validation_result
                    validated.append(vuln)
            
            results['validated'] = validated
            self.logger.info(f"Validadas {len(validated)} vulnerabilidades críticas")
            
            # Generar reporte
            self.logger.info("Generando reporte final...")
            report_path = Path(output_dir) / f"{Path(apk_path).stem}_report.json"
            ReportGenerator.generate(results, str(report_path))
            
            self.logger.info(f"Análisis completado. Reporte: {report_path}")
            return results
            
        except Exception as e:
            self.logger.error(f"Error durante el análisis: {str(e)}", exc_info=True)
            results['error'] = str(e)
            return results
    
    def analyze_batch(self, input_dir: str, output_dir: str = "results/batch/") -> List[Dict]:
        """
        Analiza múltiples APKs en batch
        
        Args:
            input_dir: Directorio con archivos APK
            output_dir: Directorio para resultados
            
        Returns:
            Lista de resultados para cada APK
        """
        apk_files = list(Path(input_dir).glob("*.apk"))
        self.logger.info(f"Analizando {len(apk_files)} APKs en modo batch...")
        
        results = []
        for i, apk_path in enumerate(apk_files, 1):
            self.logger.info(f"[{i}/{len(apk_files)}] Procesando: {apk_path.name}")
            result = self.analyze_apk(str(apk_path), output_dir)
            results.append(result)
        
        # Generar reporte consolidado
        consolidated_path = Path(output_dir) / "consolidated_report.json"
        ReportGenerator.generate_consolidated(results, str(consolidated_path))
        
        self.logger.info(f"Análisis batch completado. Reporte: {consolidated_path}")
        return results
    
    def _get_criticality(self, score: float) -> str:
        """Determina nivel de criticidad según score"""
        if score >= 0.75:
            return "CRITICAL"
        elif score >= 0.55:
            return "HIGH"
        elif score >= 0.35:
            return "MEDIUM"
        else:
            return "LOW"


def main():
    """Punto de entrada principal"""
    parser = argparse.ArgumentParser(
        description="Framework de Detección de Vulnerabilidades Android"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')
    
    # Comando: analyze
    analyze_parser = subparsers.add_parser('analyze', help='Analizar APK individual')
    analyze_parser.add_argument('--apk', required=True, help='Ruta al archivo APK')
    analyze_parser.add_argument('--output', default='results/', help='Directorio de salida')
    analyze_parser.add_argument('--config', default='config/default_config.yaml', help='Archivo de configuración')
    
    # Comando: batch
    batch_parser = subparsers.add_parser('batch', help='Análisis batch de múltiples APKs')
    batch_parser.add_argument('--input', required=True, help='Directorio con APKs')
    batch_parser.add_argument('--output', default='results/batch/', help='Directorio de salida')
    batch_parser.add_argument('--config', default='config/default_config.yaml', help='Archivo de configuración')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Inicializar framework
    framework = VulnerabilityDetectionFramework(args.config)
    
    # Ejecutar comando
    if args.command == 'analyze':
        framework.analyze_apk(args.apk, args.output)
    elif args.command == 'batch':
        framework.analyze_batch(args.input, args.output)


if __name__ == "__main__":
    main()

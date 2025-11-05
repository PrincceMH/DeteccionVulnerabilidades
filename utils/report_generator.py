"""
Generador de reportes de vulnerabilidades
"""

import json
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime


class ReportGenerator:
    """Genera reportes en múltiples formatos"""
    
    @staticmethod
    def generate(results: Dict[str, Any], output_path: str) -> None:
        """
        Genera reporte individual de análisis
        
        Args:
            results: Diccionario con resultados del análisis
            output_path: Ruta donde guardar el reporte
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Agregar timestamp
        results['timestamp'] = datetime.now().isoformat()
        results['summary'] = ReportGenerator._generate_summary(results)
        
        # Guardar como JSON
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        # Generar versión HTML
        html_path = output_file.with_suffix('.html')
        ReportGenerator._generate_html(results, str(html_path))
    
    @staticmethod
    def generate_consolidated(results_list: List[Dict], output_path: str) -> None:
        """
        Genera reporte consolidado de múltiples análisis
        
        Args:
            results_list: Lista de resultados individuales
            output_path: Ruta donde guardar el reporte consolidado
        """
        consolidated = {
            'timestamp': datetime.now().isoformat(),
            'total_apks': len(results_list),
            'total_vulnerabilities': sum(len(r.get('vulnerabilities', [])) for r in results_list),
            'total_validated': sum(len(r.get('validated', [])) for r in results_list),
            'results': results_list,
            'statistics': ReportGenerator._calculate_statistics(results_list)
        }
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(consolidated, f, indent=2, ensure_ascii=False)
    
    @staticmethod
    def _generate_summary(results: Dict[str, Any]) -> Dict[str, Any]:
        """Genera resumen ejecutivo"""
        vulnerabilities = results.get('vulnerabilities', [])
        
        summary = {
            'total_flows': len(results.get('taint_flows', [])),
            'total_vulnerabilities': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v['criticality'] == 'CRITICAL'),
            'high': sum(1 for v in vulnerabilities if v['criticality'] == 'HIGH'),
            'medium': sum(1 for v in vulnerabilities if v['criticality'] == 'MEDIUM'),
            'low': sum(1 for v in vulnerabilities if v['criticality'] == 'LOW'),
            'validated': len(results.get('validated', []))
        }
        
        return summary
    
    @staticmethod
    def _calculate_statistics(results_list: List[Dict]) -> Dict[str, Any]:
        """Calcula estadísticas agregadas"""
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results_list)
        
        stats = {
            'avg_vulnerabilities_per_apk': total_vulns / len(results_list) if results_list else 0,
            'apks_with_critical': sum(1 for r in results_list 
                                     if any(v['criticality'] == 'CRITICAL' 
                                           for v in r.get('vulnerabilities', []))),
            'validation_rate': sum(len(r.get('validated', [])) for r in results_list) / total_vulns 
                              if total_vulns > 0 else 0
        }
        
        return stats
    
    @staticmethod
    def _generate_html(results: Dict[str, Any], output_path: str) -> None:
        """Genera versión HTML del reporte"""
        summary = results.get('summary', {})
        
        html_content = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Vulnerabilidades - {Path(results['apk_path']).name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; 
                      border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                   gap: 15px; margin: 20px 0; }}
        .metric {{ background: #f8f9fa; padding: 20px; border-radius: 5px; text-align: center; }}
        .metric-value {{ font-size: 32px; font-weight: bold; color: #007bff; }}
        .metric-label {{ color: #666; margin-top: 5px; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .vuln-list {{ margin: 20px 0; }}
        .vuln-item {{ background: #fff; border-left: 4px solid #007bff; padding: 15px; 
                     margin: 10px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .timestamp {{ color: #888; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Reporte de Análisis de Vulnerabilidades</h1>
        <p class="timestamp">Generado: {results.get('timestamp', 'N/A')}</p>
        <p><strong>APK:</strong> {results['apk_path']}</p>
        
        <h2>Resumen Ejecutivo</h2>
        <div class="summary">
            <div class="metric">
                <div class="metric-value">{summary.get('total_flows', 0)}</div>
                <div class="metric-label">Flujos Detectados</div>
            </div>
            <div class="metric">
                <div class="metric-value">{summary.get('total_vulnerabilities', 0)}</div>
                <div class="metric-label">Vulnerabilidades</div>
            </div>
            <div class="metric">
                <div class="metric-value critical">{summary.get('critical', 0)}</div>
                <div class="metric-label">Críticas</div>
            </div>
            <div class="metric">
                <div class="metric-value high">{summary.get('high', 0)}</div>
                <div class="metric-label">Altas</div>
            </div>
            <div class="metric">
                <div class="metric-value">{summary.get('validated', 0)}</div>
                <div class="metric-label">Validadas</div>
            </div>
        </div>
        
        <h2>Vulnerabilidades Detectadas</h2>
        <div class="vuln-list">
        """
        
        for i, vuln in enumerate(results.get('vulnerabilities', []), 1):
            criticality = vuln['criticality'].lower()
            html_content += f"""
            <div class="vuln-item">
                <h3 class="{criticality}">#{i} - {vuln['criticality']}</h3>
                <p><strong>Score:</strong> {vuln['score']:.3f}</p>
                <p><strong>Flujo:</strong> {vuln['flow'].get('source', 'N/A')} → 
                   {vuln['flow'].get('sink', 'N/A')}</p>
                {'<p><strong>✓ Validada dinámicamente</strong></p>' if vuln.get('validated') else ''}
            </div>
            """
        
        html_content += """
        </div>
    </div>
</body>
</html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

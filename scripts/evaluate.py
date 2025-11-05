"""
Script de evaluación del framework completo
Genera métricas, comparaciones con baselines, y visualizaciones
"""

import argparse
import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Any
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
    confusion_matrix, classification_report, roc_curve, auc,
    precision_recall_curve
)
import pandas as pd
from scipy import stats

import sys
sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import setup_logger
from utils.config_loader import load_config


class Evaluator:
    """Evaluador del framework completo"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: Configuración del sistema
        """
        self.config = config
        self.logger = setup_logger("Evaluator", config['logging']['level'])
        
        # Métricas objetivo de la tesis
        self.target_metrics = {
            'precision': (0.85, 0.89),  # Rango objetivo
            'recall': (0.82, 0.86),
            'f1': (0.84, 0.87),
            'fpr': (0.20, 0.25)  # False Positive Rate
        }
    
    def evaluate_framework(
        self,
        predictions: List[Dict[str, Any]],
        ground_truth: List[Dict[str, Any]],
        output_dir: str = "results/evaluation/"
    ) -> Dict[str, Any]:
        """
        Evalúa el framework completo
        
        Args:
            predictions: Predicciones del framework
            ground_truth: Ground truth del dataset
            output_dir: Directorio para guardar resultados
            
        Returns:
            Diccionario con todas las métricas
        """
        self.logger.info("="*80)
        self.logger.info("EVALUACIÓN DEL FRAMEWORK")
        self.logger.info("="*80)
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # 1. Extraer labels y scores
        y_true, y_pred, y_scores = self._prepare_data(predictions, ground_truth)
        
        # 2. Calcular métricas principales
        metrics = self._calculate_metrics(y_true, y_pred, y_scores)
        
        # 3. Generar matriz de confusión
        self._plot_confusion_matrix(y_true, y_pred, output_path)
        
        # 4. Curvas ROC y Precision-Recall
        self._plot_roc_curve(y_true, y_scores, output_path)
        self._plot_precision_recall_curve(y_true, y_scores, output_path)
        
        # 5. Distribución de scores
        self._plot_score_distribution(y_true, y_scores, output_path)
        
        # 6. Análisis de errores
        error_analysis = self._analyze_errors(predictions, ground_truth, y_true, y_pred)
        
        # 7. Comparación con targets
        comparison = self._compare_with_targets(metrics)
        
        # 8. Guardar resultados
        results = {
            'metrics': metrics,
            'error_analysis': error_analysis,
            'target_comparison': comparison
        }
        
        results_file = output_path / "evaluation_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # 9. Generar reporte
        self._generate_report(results, output_path)
        
        self.logger.info(f"\n✓ Evaluación completada. Resultados en: {output_path}")
        
        return results
    
    def compare_with_baselines(
        self,
        our_results: Dict[str, Any],
        baseline_results: Dict[str, Dict[str, Any]],
        output_dir: str = "results/comparison/"
    ) -> Dict[str, Any]:
        """
        Compara framework con herramientas baseline
        
        Args:
            our_results: Resultados de nuestro framework
            baseline_results: Dict con resultados de baselines
            output_dir: Directorio para guardar comparación
            
        Returns:
            Resultados de comparación estadística
        """
        self.logger.info("\n" + "="*80)
        self.logger.info("COMPARACIÓN CON BASELINES")
        self.logger.info("="*80)
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # 1. Crear tabla comparativa
        comparison_table = self._create_comparison_table(our_results, baseline_results)
        
        # 2. Tests estadísticos
        statistical_tests = self._run_statistical_tests(our_results, baseline_results)
        
        # 3. Visualizaciones comparativas
        self._plot_comparative_metrics(comparison_table, output_path)
        self._plot_radar_chart(comparison_table, output_path)
        
        # 4. Guardar tabla
        comparison_table.to_csv(output_path / "comparison_table.csv", index=False)
        comparison_table.to_latex(output_path / "comparison_table.tex", index=False)
        
        results = {
            'comparison_table': comparison_table.to_dict(),
            'statistical_tests': statistical_tests
        }
        
        with open(output_path / "comparison_results.json", 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def _prepare_data(
        self,
        predictions: List[Dict],
        ground_truth: List[Dict]
    ) -> tuple:
        """Prepara datos para evaluación"""
        
        y_true = []
        y_pred = []
        y_scores = []
        
        # Mapear predictions a ground truth
        gt_dict = {item['id']: item for item in ground_truth}
        
        for pred in predictions:
            pred_id = pred['id']
            
            if pred_id in gt_dict:
                # Label real
                y_true.append(gt_dict[pred_id]['is_vulnerable'])
                
                # Predicción binaria
                score = pred['score']
                y_pred.append(1 if score >= 0.5 else 0)
                
                # Score continuo
                y_scores.append(score)
        
        return (
            np.array(y_true),
            np.array(y_pred),
            np.array(y_scores)
        )
    
    def _calculate_metrics(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_scores: np.ndarray
    ) -> Dict[str, float]:
        """Calcula todas las métricas"""
        
        # Métricas básicas
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        accuracy = accuracy_score(y_true, y_pred)
        
        # Confusion matrix
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        
        # False Positive Rate
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        
        # Specificity
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        
        # AUC
        if len(np.unique(y_true)) > 1:
            fpr_curve, tpr_curve, _ = roc_curve(y_true, y_scores)
            roc_auc = auc(fpr_curve, tpr_curve)
        else:
            roc_auc = 0.0
        
        metrics = {
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'accuracy': round(accuracy, 4),
            'fpr': round(fpr, 4),
            'specificity': round(specificity, 4),
            'auc_roc': round(roc_auc, 4),
            'true_positives': int(tp),
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn)
        }
        
        # Logging
        self.logger.info("\nMÉTRICAS PRINCIPALES:")
        self.logger.info(f"  Precisión:     {metrics['precision']:.2%}")
        self.logger.info(f"  Recall:        {metrics['recall']:.2%}")
        self.logger.info(f"  F1-Score:      {metrics['f1_score']:.2%}")
        self.logger.info(f"  Accuracy:      {metrics['accuracy']:.2%}")
        self.logger.info(f"  FPR:           {metrics['fpr']:.2%}")
        self.logger.info(f"  AUC-ROC:       {metrics['auc_roc']:.4f}")
        
        return metrics
    
    def _plot_confusion_matrix(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        output_path: Path
    ):
        """Genera y guarda matriz de confusión"""
        
        cm = confusion_matrix(y_true, y_pred)
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(
            cm,
            annot=True,
            fmt='d',
            cmap='Blues',
            xticklabels=['Benigno', 'Vulnerable'],
            yticklabels=['Benigno', 'Vulnerable']
        )
        plt.title('Matriz de Confusión', fontsize=14, fontweight='bold')
        plt.ylabel('Real', fontsize=12)
        plt.xlabel('Predicho', fontsize=12)
        plt.tight_layout()
        plt.savefig(output_path / 'confusion_matrix.png', dpi=300)
        plt.close()
        
        self.logger.info("✓ Matriz de confusión generada")
    
    def _plot_roc_curve(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        output_path: Path
    ):
        """Genera curva ROC"""
        
        if len(np.unique(y_true)) < 2:
            return
        
        fpr, tpr, thresholds = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)
        
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC (AUC = {roc_auc:.3f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate', fontsize=12)
        plt.ylabel('True Positive Rate', fontsize=12)
        plt.title('Curva ROC', fontsize=14, fontweight='bold')
        plt.legend(loc="lower right")
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_path / 'roc_curve.png', dpi=300)
        plt.close()
        
        self.logger.info("✓ Curva ROC generada")
    
    def _plot_precision_recall_curve(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        output_path: Path
    ):
        """Genera curva Precision-Recall"""
        
        if len(np.unique(y_true)) < 2:
            return
        
        precision, recall, thresholds = precision_recall_curve(y_true, y_scores)
        
        plt.figure(figsize=(8, 6))
        plt.plot(recall, precision, color='blue', lw=2)
        plt.xlabel('Recall', fontsize=12)
        plt.ylabel('Precision', fontsize=12)
        plt.title('Curva Precision-Recall', fontsize=14, fontweight='bold')
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_path / 'precision_recall_curve.png', dpi=300)
        plt.close()
        
        self.logger.info("✓ Curva Precision-Recall generada")
    
    def _plot_score_distribution(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        output_path: Path
    ):
        """Genera distribución de scores por clase"""
        
        plt.figure(figsize=(10, 6))
        
        # Scores de benignos
        benign_scores = y_scores[y_true == 0]
        plt.hist(benign_scores, bins=50, alpha=0.5, label='Benigno', color='green')
        
        # Scores de vulnerables
        vuln_scores = y_scores[y_true == 1]
        plt.hist(vuln_scores, bins=50, alpha=0.5, label='Vulnerable', color='red')
        
        # Umbral
        plt.axvline(x=0.5, color='black', linestyle='--', linewidth=2, label='Umbral (0.5)')
        
        plt.xlabel('Score de Criticidad', fontsize=12)
        plt.ylabel('Frecuencia', fontsize=12)
        plt.title('Distribución de Scores por Clase', fontsize=14, fontweight='bold')
        plt.legend()
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_path / 'score_distribution.png', dpi=300)
        plt.close()
        
        self.logger.info("✓ Distribución de scores generada")
    
    def _analyze_errors(
        self,
        predictions: List[Dict],
        ground_truth: List[Dict],
        y_true: np.ndarray,
        y_pred: np.ndarray
    ) -> Dict[str, Any]:
        """Analiza errores del modelo"""
        
        # Identificar FP y FN
        fp_indices = np.where((y_pred == 1) & (y_true == 0))[0]
        fn_indices = np.where((y_pred == 0) & (y_true == 1))[0]
        
        error_analysis = {
            'total_errors': int(len(fp_indices) + len(fn_indices)),
            'false_positives': int(len(fp_indices)),
            'false_negatives': int(len(fn_indices)),
            'fp_patterns': [],
            'fn_patterns': []
        }
        
        self.logger.info(f"\nANÁLISIS DE ERRORES:")
        self.logger.info(f"  Total errores:      {error_analysis['total_errors']}")
        self.logger.info(f"  Falsos positivos:   {error_analysis['false_positives']}")
        self.logger.info(f"  Falsos negativos:   {error_analysis['false_negatives']}")
        
        return error_analysis
    
    def _compare_with_targets(self, metrics: Dict[str, float]) -> Dict[str, Any]:
        """Compara métricas con objetivos de la tesis"""
        
        comparison = {}
        
        self.logger.info("\nCOMPARACIÓN CON OBJETIVOS:")
        
        for metric, (min_target, max_target) in self.target_metrics.items():
            if metric in metrics:
                value = metrics[metric]
                within_target = min_target <= value <= max_target
                
                comparison[metric] = {
                    'value': value,
                    'target_range': (min_target, max_target),
                    'within_target': within_target,
                    'status': '✓' if within_target else '✗'
                }
                
                self.logger.info(
                    f"  {metric.capitalize():15} {value:.2%}  "
                    f"[Target: {min_target:.2%}-{max_target:.2%}] "
                    f"{comparison[metric]['status']}"
                )
        
        return comparison
    
    def _create_comparison_table(
        self,
        our_results: Dict[str, Any],
        baseline_results: Dict[str, Dict[str, Any]]
    ) -> pd.DataFrame:
        """Crea tabla comparativa con baselines"""
        
        data = []
        
        # Nuestros resultados
        data.append({
            'Herramienta': 'Framework Propuesto',
            'Metodología': 'Taint + Transformer + Validación',
            'Precisión': our_results['metrics']['precision'],
            'Recall': our_results['metrics']['recall'],
            'F1-Score': our_results['metrics']['f1_score'],
            'FPR': our_results['metrics']['fpr']
        })
        
        # Baselines
        for tool_name, tool_results in baseline_results.items():
            data.append({
                'Herramienta': tool_name,
                'Metodología': tool_results.get('methodology', 'N/A'),
                'Precisión': tool_results['metrics']['precision'],
                'Recall': tool_results['metrics']['recall'],
                'F1-Score': tool_results['metrics']['f1_score'],
                'FPR': tool_results['metrics']['fpr']
            })
        
        df = pd.DataFrame(data)
        
        self.logger.info("\nTABLA COMPARATIVA:")
        print(df.to_string(index=False))
        
        return df
    
    def _run_statistical_tests(
        self,
        our_results: Dict,
        baseline_results: Dict
    ) -> Dict[str, Any]:
        """Ejecuta tests estadísticos (McNemar, Wilcoxon)"""
        
        tests = {}
        
        # Implementación simplificada
        self.logger.info("\nTests estadísticos: Implementación pendiente")
        
        return tests
    
    def _plot_comparative_metrics(self, df: pd.DataFrame, output_path: Path):
        """Genera gráfico comparativo de métricas"""
        
        metrics = ['Precisión', 'Recall', 'F1-Score']
        
        df_plot = df.set_index('Herramienta')[metrics]
        
        ax = df_plot.plot(kind='bar', figsize=(12, 6), rot=45)
        plt.title('Comparación de Métricas por Herramienta', fontsize=14, fontweight='bold')
        plt.ylabel('Score', fontsize=12)
        plt.xlabel('Herramienta', fontsize=12)
        plt.legend(title='Métrica')
        plt.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_path / 'comparative_metrics.png', dpi=300)
        plt.close()
        
        self.logger.info("✓ Gráfico comparativo generado")
    
    def _plot_radar_chart(self, df: pd.DataFrame, output_path: Path):
        """Genera radar chart comparativo"""
        
        metrics = ['Precisión', 'Recall', 'F1-Score']
        
        fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(projection='polar'))
        
        angles = np.linspace(0, 2 * np.pi, len(metrics), endpoint=False).tolist()
        angles += angles[:1]
        
        for _, row in df.iterrows():
            values = [row[m] for m in metrics]
            values += values[:1]
            ax.plot(angles, values, 'o-', linewidth=2, label=row['Herramienta'])
            ax.fill(angles, values, alpha=0.15)
        
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(metrics)
        ax.set_ylim(0, 1)
        ax.set_title('Comparación Multi-Métrica', fontsize=14, fontweight='bold', pad=20)
        ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1))
        ax.grid(True)
        
        plt.tight_layout()
        plt.savefig(output_path / 'radar_chart.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info("✓ Radar chart generado")
    
    def _generate_report(self, results: Dict[str, Any], output_path: Path):
        """Genera reporte HTML completo"""
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Reporte de Evaluación - Framework Android</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; 
                     border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .metric-card {{ background: #ecf0f1; padding: 20px; border-radius: 5px; text-align: center; }}
        .metric-value {{ font-size: 32px; font-weight: bold; color: #3498db; }}
        .metric-label {{ color: #7f8c8d; margin-top: 5px; }}
        .success {{ color: #27ae60; }}
        .warning {{ color: #f39c12; }}
        .error {{ color: #e74c3c; }}
        img {{ max-width: 100%; height: auto; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Reporte de Evaluación del Framework</h1>
        <p><strong>Fecha:</strong> {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>Métricas Principales</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">{results['metrics']['precision']:.2%}</div>
                <div class="metric-label">Precisión</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{results['metrics']['recall']:.2%}</div>
                <div class="metric-label">Recall</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{results['metrics']['f1_score']:.2%}</div>
                <div class="metric-label">F1-Score</div>
            </div>
        </div>
        
        <h2>Visualizaciones</h2>
        <img src="confusion_matrix.png" alt="Matriz de Confusión">
        <img src="roc_curve.png" alt="Curva ROC">
        <img src="score_distribution.png" alt="Distribución de Scores">
        
        <h2>Comparación con Objetivos</h2>
        <table>
            <tr>
                <th>Métrica</th>
                <th>Valor Obtenido</th>
                <th>Rango Objetivo</th>
                <th>Estado</th>
            </tr>
"""
        
        for metric, data in results['target_comparison'].items():
            status_class = 'success' if data['within_target'] else 'error'
            html += f"""
            <tr>
                <td>{metric.capitalize()}</td>
                <td>{data['value']:.2%}</td>
                <td>{data['target_range'][0]:.2%} - {data['target_range'][1]:.2%}</td>
                <td class="{status_class}">{data['status']}</td>
            </tr>
"""
        
        html += """
        </table>
    </div>
</body>
</html>
"""
        
        report_file = output_path / "evaluation_report.html"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        self.logger.info(f"✓ Reporte HTML generado: {report_file}")


def main():
    """Punto de entrada principal"""
    
    parser = argparse.ArgumentParser(description="Evaluación del framework")
    parser.add_argument(
        '--config',
        type=str,
        default='config/default_config.yaml',
        help='Archivo de configuración'
    )
    parser.add_argument(
        '--predictions',
        type=str,
        required=True,
        help='Archivo JSON con predicciones'
    )
    parser.add_argument(
        '--ground-truth',
        type=str,
        required=True,
        help='Archivo JSON con ground truth'
    )
    parser.add_argument(
        '--baselines',
        type=str,
        help='Archivo JSON con resultados de baselines (opcional)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='results/evaluation/',
        help='Directorio de salida'
    )
    
    args = parser.parse_args()
    
    # Cargar configuración
    config = load_config(args.config)
    
    # Cargar datos
    with open(args.predictions, 'r') as f:
        predictions = json.load(f)
    
    with open(args.ground_truth, 'r') as f:
        ground_truth = json.load(f)
    
    # Inicializar evaluador
    evaluator = Evaluator(config)
    
    # Evaluar
    results = evaluator.evaluate_framework(
        predictions,
        ground_truth,
        output_dir=args.output
    )
    
    # Comparar con baselines si están disponibles
    if args.baselines:
        with open(args.baselines, 'r') as f:
            baselines = json.load(f)
        
        evaluator.compare_with_baselines(
            results,
            baselines,
            output_dir=args.output + "/comparison/"
        )


if __name__ == "__main__":
    main()

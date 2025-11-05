"""
Script de demostración del framework
Genera datos sintéticos y muestra el flujo completo
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import setup_logger
from utils.config_loader import load_config
import json
import numpy as np

# Configurar logging
logger = setup_logger("Demo", "INFO")

def generate_synthetic_dataset(num_vulnerable=100, num_benign=300):
    """
    Genera dataset sintético para demostración
    
    Returns:
        Dict con flujos y labels
    """
    logger.info("Generando dataset sintético...")
    
    flows = []
    labels = []
    
    # Generar flujos vulnerables
    for i in range(num_vulnerable):
        flow = {
            'id': f'vuln_{i}',
            'source': 'android.location.LocationManager: getLastKnownLocation',
            'sink': 'java.net.HttpURLConnection: connect',
            'api_sequence': [
                'LocationManager.getLastKnownLocation',
                'String.valueOf',
                'HttpURLConnection.setRequestProperty',
                'HttpURLConnection.connect'
            ],
            'permissions': ['ACCESS_FINE_LOCATION', 'INTERNET'],
            'components': ['MainActivity'],
            'criticality_score': np.random.uniform(0.7, 0.95),
            'has_encryption': False
        }
        flows.append(flow)
        labels.append(1)  # Vulnerable
    
    # Generar flujos benignos
    for i in range(num_benign):
        flow = {
            'id': f'benign_{i}',
            'source': 'android.location.LocationManager: getLastKnownLocation',
            'sink': 'android.widget.TextView: setText',
            'api_sequence': [
                'LocationManager.getLastKnownLocation',
                'Location.getLatitude',
                'TextView.setText'
            ],
            'permissions': ['ACCESS_FINE_LOCATION'],
            'components': ['MainActivity'],
            'criticality_score': np.random.uniform(0.1, 0.4),
            'has_encryption': False
        }
        flows.append(flow)
        labels.append(0)  # Benigno
    
    dataset = {
        'flows': flows,
        'labels': labels,
        'metadata': {
            'total': len(flows),
            'vulnerable': num_vulnerable,
            'benign': num_benign
        }
    }
    
    logger.info(f"✓ Dataset generado: {len(flows)} flujos ({num_vulnerable} vulnerables, {num_benign} benignos)")
    
    return dataset


def generate_ground_truth(dataset):
    """Genera ground truth para evaluación"""
    
    ground_truth = []
    
    for flow, label in zip(dataset['flows'], dataset['labels']):
        ground_truth.append({
            'id': flow['id'],
            'is_vulnerable': label,
            'vulnerability_type': 'Data Leakage' if label == 1 else 'None'
        })
    
    return ground_truth


def generate_synthetic_predictions(ground_truth, accuracy=0.87):
    """
    Genera predicciones sintéticas con accuracy objetivo
    """
    logger.info(f"Generando predicciones sintéticas (accuracy objetivo: {accuracy:.2%})...")
    
    predictions = []
    num_samples = len(ground_truth)
    num_correct = int(num_samples * accuracy)
    
    # Indices para muestras correctas e incorrectas
    indices = np.arange(num_samples)
    np.random.shuffle(indices)
    correct_indices = set(indices[:num_correct])
    
    for idx, gt in enumerate(ground_truth):
        is_correct = idx in correct_indices
        
        if is_correct:
            # Predicción correcta
            if gt['is_vulnerable']:
                score = np.random.uniform(0.7, 0.95)
            else:
                score = np.random.uniform(0.1, 0.4)
        else:
            # Predicción incorrecta
            if gt['is_vulnerable']:
                score = np.random.uniform(0.1, 0.4)  # False negative
            else:
                score = np.random.uniform(0.6, 0.85)  # False positive
        
        predictions.append({
            'id': gt['id'],
            'score': score,
            'predicted_vulnerable': score >= 0.5
        })
    
    logger.info(f"✓ Predicciones generadas")
    
    return predictions


def generate_baseline_results():
    """
    Genera resultados sintéticos de herramientas baseline
    """
    baselines = {
        'FlowDroid': {
            'methodology': 'Análisis taint tradicional',
            'metrics': {
                'precision': 0.54,
                'recall': 0.92,
                'f1_score': 0.68,
                'fpr': 0.45
            }
        },
        'MobSF': {
            'methodology': 'Análisis híbrido estático-dinámico',
            'metrics': {
                'precision': 0.61,
                'recall': 0.85,
                'f1_score': 0.71,
                'fpr': 0.39
            }
        },
        'Li et al.': {
            'methodology': 'Taint de grano fino + grafos',
            'metrics': {
                'precision': 0.72,
                'recall': 0.81,
                'f1_score': 0.76,
                'fpr': 0.28
            }
        },
        'A2 Agéntico': {
            'methodology': 'Detección + validación agéntica',
            'metrics': {
                'precision': 0.79,
                'recall': 0.78,
                'f1_score': 0.78,
                'fpr': 0.21
            }
        }
    }
    
    return baselines


def main():
    """Ejecuta demostración completa"""
    
    logger.info("="*80)
    logger.info("DEMOSTRACIÓN DEL FRAMEWORK")
    logger.info("="*80)
    
    # Crear directorios
    datasets_dir = Path("datasets/synthetic/")
    results_dir = Path("results/demo/")
    datasets_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Generar dataset sintético
    logger.info("\n[1/5] Generando dataset sintético...")
    dataset = generate_synthetic_dataset(num_vulnerable=100, num_benign=300)
    
    dataset_file = datasets_dir / "synthetic_dataset.json"
    with open(dataset_file, 'w') as f:
        json.dump(dataset, f, indent=2)
    logger.info(f"✓ Dataset guardado: {dataset_file}")
    
    # 2. Generar ground truth
    logger.info("\n[2/5] Generando ground truth...")
    ground_truth = generate_ground_truth(dataset)
    
    gt_file = datasets_dir / "ground_truth.json"
    with open(gt_file, 'w') as f:
        json.dump(ground_truth, f, indent=2)
    logger.info(f"✓ Ground truth guardado: {gt_file}")
    
    # 3. Generar predicciones sintéticas
    logger.info("\n[3/5] Generando predicciones sintéticas...")
    predictions = generate_synthetic_predictions(ground_truth, accuracy=0.87)
    
    pred_file = results_dir / "predictions.json"
    with open(pred_file, 'w') as f:
        json.dump(predictions, f, indent=2)
    logger.info(f"✓ Predicciones guardadas: {pred_file}")
    
    # 4. Generar resultados de baselines
    logger.info("\n[4/5] Generando resultados de baselines...")
    baselines = generate_baseline_results()
    
    baseline_file = results_dir / "baseline_results.json"
    with open(baseline_file, 'w') as f:
        json.dump(baselines, f, indent=2)
    logger.info(f"✓ Baselines guardados: {baseline_file}")
    
    # 5. Instrucciones para evaluación
    logger.info("\n[5/5] Configuración completada")
    logger.info("\n" + "="*80)
    logger.info("SIGUIENTE PASO: EVALUACIÓN")
    logger.info("="*80)
    logger.info("\nEjecuta el siguiente comando para evaluar:")
    logger.info(f"\npython scripts/evaluate.py \\")
    logger.info(f"    --predictions {pred_file} \\")
    logger.info(f"    --ground-truth {gt_file} \\")
    logger.info(f"    --baselines {baseline_file} \\")
    logger.info(f"    --output results/evaluation/")
    
    logger.info("\n✓ Demostración completada exitosamente")


if __name__ == "__main__":
    main()

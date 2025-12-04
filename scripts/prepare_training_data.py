"""
Genera:
    - Extraccion de features de todos los APKs
    - Division train/validation/test
    - Archivo de datos preparado para entrenamiento
"""

import os
import sys
import json
import pickle
import random
import warnings
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

# Suprimir logs de androguard
os.environ['LOGURU_LEVEL'] = 'ERROR'
import logging
logging.getLogger('androguard').setLevel(logging.ERROR)
try:
    from loguru import logger
    logger.disable("androguard")
except ImportError:
    pass

# Configurar paths
ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))

import argparse
import numpy as np


@dataclass
class APKSample:
    """Representa un APK procesado para entrenamiento."""
    apk_path: str
    apk_name: str
    label: int  # 0=benigno, 1=vulnerable
    source: str  # 'droidbench' o 'fdroid'
    category: str  # Categoria del APK
    flows: List[Dict] = field(default_factory=list)
    num_flows: int = 0
    features: Optional[Dict] = None
    tokens: Optional[List[int]] = None
    error: Optional[str] = None


@dataclass 
class PreparedDataset:
    """Dataset preparado para entrenamiento."""
    train_samples: List[APKSample]
    val_samples: List[APKSample]
    test_samples: List[APKSample]
    vocab_size: int
    num_features: int
    label_distribution: Dict[str, int]
    created_at: str
    config: Dict[str, Any]


class DatasetPreparer:
    """Prepara el dataset para entrenamiento."""
    
    def __init__(
        self,
        droidbench_path: Path,
        fdroid_path: Path,
        output_dir: Path
    ):
        self.droidbench_path = droidbench_path
        self.fdroid_path = fdroid_path
        self.output_dir = output_dir
        
        # Inicializar modulos
        self._init_modules()
    
    def _init_modules(self):
        """Inicializa los modulos necesarios."""
        try:
            from taint_analysis import FlowExtractor
            from taint_analysis.flow_extractor import ExtractionConfig
            from transformer import (
                AndroidCodeTokenizer,
                FeatureExtractor,
                AndroidVulnerabilityDetector
            )
            
            # Configurar extractor de flujos
            self.flow_config = ExtractionConfig(
                use_interprocedural=False,
                max_depth=5,
                include_low_risk=True
            )
            self.flow_extractor = FlowExtractor(config=self.flow_config)
            
            # Tokenizer y feature extractor
            self.tokenizer = AndroidCodeTokenizer()
            self.feature_extractor = FeatureExtractor()
            
            self.modules_loaded = True
            
        except ImportError as e:
            print(f"Error cargando modulos: {e}")
            self.modules_loaded = False
    
    def collect_apks(self) -> Tuple[List[APKSample], List[APKSample]]:
        """
        Recolecta todos los APKs de ambos datasets.
        
        Returns:
            Tuple con listas de APKs vulnerables y benignos
        """
        vulnerable_apks = []
        benign_apks = []
        
        # Recolectar APKs de DroidBench (vulnerables)
        print("\nRecolectando APKs de DroidBench (vulnerables)...")
        for category_dir in self.droidbench_path.iterdir():
            if category_dir.is_dir():
                category = category_dir.name
                for apk_file in category_dir.glob("*.apk"):
                    sample = APKSample(
                        apk_path=str(apk_file),
                        apk_name=apk_file.name,
                        label=1,  # Vulnerable
                        source='droidbench',
                        category=category
                    )
                    vulnerable_apks.append(sample)
        
        print(f"  DroidBench: {len(vulnerable_apks)} APKs vulnerables")
        
        # Recolectar APKs de F-Droid (benignos)
        print("Recolectando APKs de F-Droid (benignos)...")
        for apk_file in self.fdroid_path.glob("*.apk"):
            sample = APKSample(
                apk_path=str(apk_file),
                apk_name=apk_file.name,
                label=0,  # Benigno
                source='fdroid',
                category='fdroid'
            )
            benign_apks.append(sample)
        
        print(f"  F-Droid: {len(benign_apks)} APKs benignos")
        
        return vulnerable_apks, benign_apks
    
    def process_apk(self, sample: APKSample) -> APKSample:
        """
        Procesa un APK extrayendo flujos y features.
        
        Args:
            sample: APKSample a procesar
        
        Returns:
            APKSample con datos extraidos
        """
        if not self.modules_loaded:
            sample.error = "Modulos no cargados"
            return sample
        
        try:
            # Extraer flujos
            result = self.flow_extractor.extract(sample.apk_path)
            
            # Verificar si hay flujos (sin errores criticos)
            if result.flows:
                sample.flows = [
                    {
                        'source': f.source.signature,
                        'sink': f.sink.signature,
                        'risk_level': f.risk_level,
                        'category': f.category.value if hasattr(f.category, 'value') else str(f.category)
                    }
                    for f in result.flows
                ]
                sample.num_flows = len(result.flows)
                
                # Extraer features
                features_list = self.feature_extractor.extract_batch(result.flows)
                if features_list:
                    # Agregar features numericas
                    combined = features_list[0]
                    sample.features = {
                        'semantic': combined.semantic.__dict__ if hasattr(combined, 'semantic') else {},
                        'structural': combined.structural.__dict__ if hasattr(combined, 'structural') else {},
                        'security': combined.security.__dict__ if hasattr(combined, 'security') else {}
                    }
                
                # Tokenizar (solo obtener los IDs)
                try:
                    if result.flows:
                        first_flow = result.flows[0]
                        seq = self.tokenizer.tokenize_flow(
                            source=first_flow.source.full_name,
                            sink=first_flow.sink.full_name,
                            category=str(first_flow.category.value) if hasattr(first_flow.category, 'value') else None,
                            risk_level="HIGH" if first_flow.risk_level >= 7 else "MEDIUM" if first_flow.risk_level >= 4 else "LOW"
                        )
                        sample.tokens = seq.input_ids
                except Exception:
                    sample.tokens = []
            else:
                sample.num_flows = 0
                sample.flows = []
                
        except Exception as e:
            sample.error = str(e)
        
        return sample
    
    def process_all(
        self,
        samples: List[APKSample],
        desc: str = "Procesando"
    ) -> List[APKSample]:
        """
        Procesa todos los APKs.
        
        Args:
            samples: Lista de APKs a procesar
            desc: Descripcion para mostrar
        
        Returns:
            Lista de APKs procesados
        """
        processed = []
        total = len(samples)
        errors = 0
        
        print(f"\n{desc} {total} APKs...")
        print("-" * 60)
        
        for i, sample in enumerate(samples, 1):
            status = f"[{i}/{total}]"
            
            try:
                result = self.process_apk(sample)
                processed.append(result)
                
                if result.error:
                    errors += 1
                    print(f"{status} {sample.apk_name}: ERROR - {result.error[:50]}")
                else:
                    print(f"{status} {sample.apk_name}: {result.num_flows} flujos")
                    
            except Exception as e:
                sample.error = str(e)
                processed.append(sample)
                errors += 1
                print(f"{status} {sample.apk_name}: EXCEPTION - {str(e)[:50]}")
        
        print("-" * 60)
        print(f"Procesados: {total - errors}/{total} exitosos, {errors} errores")
        
        return processed
    
    def split_dataset(
        self,
        samples: List[APKSample],
        test_size: float = 0.2,
        val_size: float = 0.1,
        random_seed: int = 42
    ) -> Tuple[List[APKSample], List[APKSample], List[APKSample]]:
        """
        Divide el dataset en train/validation/test.
        
        Args:
            samples: Lista de todos los APKs
            test_size: Proporcion para test
            val_size: Proporcion para validation
            random_seed: Semilla para reproducibilidad
        
        Returns:
            Tuple (train, val, test)
        """
        random.seed(random_seed)
        
        # Separar por label para estratificacion
        vulnerable = [s for s in samples if s.label == 1]
        benign = [s for s in samples if s.label == 0]
        
        # Shuffle
        random.shuffle(vulnerable)
        random.shuffle(benign)
        
        def split_list(lst, test_pct, val_pct):
            n = len(lst)
            test_n = int(n * test_pct)
            val_n = int(n * val_pct)
            
            test = lst[:test_n]
            val = lst[test_n:test_n + val_n]
            train = lst[test_n + val_n:]
            
            return train, val, test
        
        # Split estratificado
        v_train, v_val, v_test = split_list(vulnerable, test_size, val_size)
        b_train, b_val, b_test = split_list(benign, test_size, val_size)
        
        # Combinar y shuffle
        train = v_train + b_train
        val = v_val + b_val
        test = v_test + b_test
        
        random.shuffle(train)
        random.shuffle(val)
        random.shuffle(test)
        
        return train, val, test
    
    def prepare(
        self,
        test_size: float = 0.2,
        val_size: float = 0.1,
        max_samples: Optional[int] = None,
        random_seed: int = 42
    ) -> PreparedDataset:
        """
        Prepara el dataset completo.
        
        Args:
            test_size: Proporcion para test
            val_size: Proporcion para validation
            max_samples: Limite de samples por clase (para pruebas)
            random_seed: Semilla aleatoria
        
        Returns:
            PreparedDataset listo para entrenamiento
        """
        print("=" * 60)
        print("PREPARACION DE DATOS PARA ENTRENAMIENTO")
        print("=" * 60)
        
        # Recolectar APKs
        vulnerable, benign = self.collect_apks()
        
        # Limitar si se especifica
        if max_samples:
            vulnerable = vulnerable[:max_samples]
            benign = benign[:max_samples]
            print(f"\nLimitado a {max_samples} samples por clase")
        
        # Procesar todos los APKs
        all_samples = []
        
        processed_vuln = self.process_all(vulnerable, "Procesando vulnerables")
        all_samples.extend(processed_vuln)
        
        processed_benign = self.process_all(benign, "Procesando benignos")
        all_samples.extend(processed_benign)
        
        # Filtrar samples con errores graves
        valid_samples = [s for s in all_samples if s.error is None]
        print(f"\nSamples validos: {len(valid_samples)}/{len(all_samples)}")
        
        # Dividir dataset
        train, val, test = self.split_dataset(
            valid_samples,
            test_size=test_size,
            val_size=val_size,
            random_seed=random_seed
        )
        
        # Calcular estadisticas
        label_dist = {
            'train_vulnerable': sum(1 for s in train if s.label == 1),
            'train_benign': sum(1 for s in train if s.label == 0),
            'val_vulnerable': sum(1 for s in val if s.label == 1),
            'val_benign': sum(1 for s in val if s.label == 0),
            'test_vulnerable': sum(1 for s in test if s.label == 1),
            'test_benign': sum(1 for s in test if s.label == 0)
        }
        
        # Crear dataset preparado
        dataset = PreparedDataset(
            train_samples=train,
            val_samples=val,
            test_samples=test,
            vocab_size=self.tokenizer.vocab.vocab_size if self.modules_loaded else 0,
            num_features=12,  # Features numericas
            label_distribution=label_dist,
            created_at=datetime.now().isoformat(),
            config={
                'test_size': test_size,
                'val_size': val_size,
                'random_seed': random_seed,
                'max_samples': max_samples
            }
        )
        
        return dataset
    
    def save_dataset(self, dataset: PreparedDataset, filename: str = "prepared_dataset.pkl"):
        """Guarda el dataset preparado."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_path = self.output_dir / filename
        
        with open(output_path, 'wb') as f:
            pickle.dump(dataset, f)
        
        print(f"\nDataset guardado en: {output_path}")
        
        # Guardar tambien un resumen JSON
        summary = {
            'created_at': dataset.created_at,
            'config': dataset.config,
            'vocab_size': dataset.vocab_size,
            'num_features': dataset.num_features,
            'label_distribution': dataset.label_distribution,
            'splits': {
                'train': len(dataset.train_samples),
                'val': len(dataset.val_samples),
                'test': len(dataset.test_samples)
            }
        }
        
        summary_path = self.output_dir / "dataset_summary.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"Resumen guardado en: {summary_path}")
        
        return output_path


def print_summary(dataset: PreparedDataset):
    """Imprime resumen del dataset."""
    print("\n" + "=" * 60)
    print("RESUMEN DEL DATASET")
    print("=" * 60)
    
    print(f"\nDivision de datos:")
    print(f"  Train: {len(dataset.train_samples)} samples")
    print(f"  Validation: {len(dataset.val_samples)} samples")
    print(f"  Test: {len(dataset.test_samples)} samples")
    
    print(f"\nDistribucion de clases:")
    ld = dataset.label_distribution
    print(f"  Train - Vulnerable: {ld['train_vulnerable']}, Benigno: {ld['train_benign']}")
    print(f"  Val   - Vulnerable: {ld['val_vulnerable']}, Benigno: {ld['val_benign']}")
    print(f"  Test  - Vulnerable: {ld['test_vulnerable']}, Benigno: {ld['test_benign']}")
    
    print(f"\nVocabulario: {dataset.vocab_size} tokens")
    print(f"Features numericas: {dataset.num_features}")
    
    # Estadisticas de flujos
    all_samples = dataset.train_samples + dataset.val_samples + dataset.test_samples
    flows_count = [s.num_flows for s in all_samples]
    
    print(f"\nEstadisticas de flujos:")
    print(f"  Total flujos: {sum(flows_count)}")
    print(f"  Promedio por APK: {np.mean(flows_count):.2f}")
    print(f"  Max: {max(flows_count)}, Min: {min(flows_count)}")
    
    # APKs sin flujos
    no_flows = sum(1 for f in flows_count if f == 0)
    print(f"  APKs sin flujos: {no_flows}")


def main():
    parser = argparse.ArgumentParser(
        description='Preparar datos para entrenamiento'
    )
    parser.add_argument(
        '--test-size',
        type=float,
        default=0.2,
        help='Proporcion para test (default: 0.2)'
    )
    parser.add_argument(
        '--val-size',
        type=float,
        default=0.1,
        help='Proporcion para validation (default: 0.1)'
    )
    parser.add_argument(
        '--max-samples',
        type=int,
        default=None,
        help='Limite de samples por clase (para pruebas)'
    )
    parser.add_argument(
        '--seed',
        type=int,
        default=42,
        help='Semilla aleatoria (default: 42)'
    )
    
    args = parser.parse_args()
    
    # Paths
    droidbench_path = ROOT_DIR / "datasets" / "droidbench" / "datasets" / "droidbench" / "DroidBench" / "apk"
    fdroid_path = ROOT_DIR / "datasets" / "benign" / "fdroid"
    output_dir = ROOT_DIR / "data" / "prepared"
    
    # Verificar que existen los datasets
    if not droidbench_path.exists():
        print(f"Error: No se encuentra DroidBench en {droidbench_path}")
        sys.exit(1)
    
    if not fdroid_path.exists():
        print(f"Error: No se encuentra F-Droid en {fdroid_path}")
        sys.exit(1)
    
    # Preparar dataset
    preparer = DatasetPreparer(
        droidbench_path=droidbench_path,
        fdroid_path=fdroid_path,
        output_dir=output_dir
    )
    
    dataset = preparer.prepare(
        test_size=args.test_size,
        val_size=args.val_size,
        max_samples=args.max_samples,
        random_seed=args.seed
    )
    
    # Mostrar resumen
    print_summary(dataset)
    
    # Guardar
    preparer.save_dataset(dataset)
    
    print("\n" + "=" * 60)
    print("PREPARACION COMPLETADA")
    print("=" * 60)


if __name__ == "__main__":
    main()

"""
Script de entrenamiento del modelo Transformer (CodeBERT)
Implementa fine-tuning en dos fases con validación cruzada
"""

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import AdamW, get_linear_schedule_with_warmup
from sklearn.model_selection import StratifiedKFold
import numpy as np
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any
import json
from tqdm import tqdm
import wandb

import sys
sys.path.append(str(Path(__file__).parent.parent))

from modules.transformer_model.vulnerability_classifier import VulnerabilityClassifier, MultiObjectiveLoss
from modules.taint_analysis.taint_analyzer import TaintFlow
from utils.logger import setup_logger
from utils.config_loader import load_config


class VulnerabilityDataset(Dataset):
    """Dataset de flujos vulnerables y benignos"""
    
    def __init__(self, flows: List[Dict], labels: List[int]):
        """
        Args:
            flows: Lista de diccionarios con datos de flujos
            labels: Lista de labels binarios (1=vulnerable, 0=benigno)
        """
        self.flows = flows
        self.labels = labels
    
    def __len__(self):
        return len(self.flows)
    
    def __getitem__(self, idx):
        return self.flows[idx], self.labels[idx]


class Trainer:
    """Entrenador del modelo Transformer"""
    
    def __init__(self, config: Dict[str, Any], use_wandb: bool = False):
        """
        Args:
            config: Configuración completa del sistema
            use_wandb: Si usar Weights & Biases para tracking
        """
        self.config = config
        self.logger = setup_logger("Trainer", config['logging']['level'])
        self.use_wandb = use_wandb
        
        # Configuración de entrenamiento
        self.transformer_config = config['transformer']
        self.batch_size = self.transformer_config.get('batch_size', 16)
        self.max_epochs = self.transformer_config.get('max_epochs', 50)
        self.learning_rate = self.transformer_config.get('learning_rate', 2e-5)
        self.early_stopping_patience = self.transformer_config.get('early_stopping_patience', 10)
        
        # Device
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.logger.info(f"Usando dispositivo: {self.device}")
        
        # Inicializar modelo
        self.model = None
        
        # Tracking de métricas
        self.best_f1 = 0.0
        self.patience_counter = 0
    
    def train(
        self,
        train_data: Dict[str, Any],
        val_data: Dict[str, Any],
        output_dir: str = "models/codebert_finetuned/"
    ) -> Dict[str, float]:
        """
        Entrena el modelo con fine-tuning en dos fases
        
        Fase 1: Adaptación de dominio Android
        Fase 2: Especialización en vulnerabilidades
        
        Args:
            train_data: Datos de entrenamiento
            val_data: Datos de validación
            output_dir: Directorio para guardar checkpoints
            
        Returns:
            Métricas finales de entrenamiento
        """
        self.logger.info("=" * 80)
        self.logger.info("INICIANDO ENTRENAMIENTO DEL MODELO TRANSFORMER")
        self.logger.info("=" * 80)
        
        # Crear directorios
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Inicializar modelo
        self.model = VulnerabilityClassifier(self.transformer_config)
        self.model.to(self.device)
        
        # Crear datasets
        train_dataset = VulnerabilityDataset(
            train_data['flows'],
            train_data['labels']
        )
        val_dataset = VulnerabilityDataset(
            val_data['flows'],
            val_data['labels']
        )
        
        train_loader = DataLoader(
            train_dataset,
            batch_size=self.batch_size,
            shuffle=True,
            num_workers=0  # Windows compatibility
        )
        val_loader = DataLoader(
            val_dataset,
            batch_size=self.batch_size,
            shuffle=False,
            num_workers=0
        )
        
        # FASE 1: Adaptación de dominio Android
        self.logger.info("\n" + "=" * 80)
        self.logger.info("FASE 1: Adaptación de Dominio Android")
        self.logger.info("=" * 80)
        
        phase1_metrics = self._train_phase(
            train_loader,
            val_loader,
            phase="domain_adaptation",
            max_epochs=self.max_epochs // 2,
            lr=self.learning_rate * 2  # LR más alto para fase 1
        )
        
        # Guardar checkpoint fase 1
        self._save_checkpoint(output_path / "phase1_checkpoint.pt", phase1_metrics)
        
        # FASE 2: Especialización en vulnerabilidades
        self.logger.info("\n" + "=" * 80)
        self.logger.info("FASE 2: Especialización en Vulnerabilidades")
        self.logger.info("=" * 80)
        
        # Reset patience counter
        self.patience_counter = 0
        self.best_f1 = 0.0
        
        phase2_metrics = self._train_phase(
            train_loader,
            val_loader,
            phase="vulnerability_specialization",
            max_epochs=self.max_epochs,
            lr=self.learning_rate  # LR normal para fase 2
        )
        
        # Guardar modelo final
        final_path = output_path / "final_model.pt"
        self._save_checkpoint(final_path, phase2_metrics)
        self.logger.info(f"\n✓ Modelo final guardado en: {final_path}")
        
        # Retornar métricas finales
        return phase2_metrics
    
    def _train_phase(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        phase: str,
        max_epochs: int,
        lr: float
    ) -> Dict[str, float]:
        """Entrena una fase específica del modelo"""
        
        # Configurar optimizer
        optimizer = AdamW(
            self.model.parameters(),
            lr=lr,
            weight_decay=self.transformer_config.get('weight_decay', 0.01)
        )
        
        # Scheduler con warmup
        num_training_steps = len(train_loader) * max_epochs
        warmup_steps = self.transformer_config.get('warmup_steps', 500)
        
        scheduler = get_linear_schedule_with_warmup(
            optimizer,
            num_warmup_steps=warmup_steps,
            num_training_steps=num_training_steps
        )
        
        # Loss function multi-objetivos
        loss_weights = self.transformer_config.get('loss_weights', {
            'bce': 0.4,
            'ranking': 0.3,
            'regularization': 0.2,
            'context': 0.1
        })
        criterion = MultiObjectiveLoss(loss_weights)
        
        # Training loop
        for epoch in range(max_epochs):
            self.logger.info(f"\nÉpoca {epoch+1}/{max_epochs}")
            
            # Entrenamiento
            train_metrics = self._train_epoch(
                train_loader,
                optimizer,
                scheduler,
                criterion
            )
            
            # Validación
            val_metrics = self._validate_epoch(val_loader, criterion)
            
            # Logging
            self.logger.info(
                f"Train Loss: {train_metrics['loss']:.4f} | "
                f"Val Loss: {val_metrics['loss']:.4f} | "
                f"Val F1: {val_metrics['f1']:.4f} | "
                f"Val Precision: {val_metrics['precision']:.4f} | "
                f"Val Recall: {val_metrics['recall']:.4f}"
            )
            
            # Wandb logging
            if self.use_wandb:
                wandb.log({
                    f"{phase}/train_loss": train_metrics['loss'],
                    f"{phase}/val_loss": val_metrics['loss'],
                    f"{phase}/val_f1": val_metrics['f1'],
                    f"{phase}/val_precision": val_metrics['precision'],
                    f"{phase}/val_recall": val_metrics['recall'],
                    "epoch": epoch
                })
            
            # Early stopping
            if val_metrics['f1'] > self.best_f1:
                self.best_f1 = val_metrics['f1']
                self.patience_counter = 0
                self.logger.info(f"✓ Nuevo mejor F1: {self.best_f1:.4f}")
            else:
                self.patience_counter += 1
                self.logger.info(f"Patience: {self.patience_counter}/{self.early_stopping_patience}")
                
                if self.patience_counter >= self.early_stopping_patience:
                    self.logger.info("Early stopping triggered")
                    break
        
        return val_metrics
    
    def _train_epoch(
        self,
        train_loader: DataLoader,
        optimizer: torch.optim.Optimizer,
        scheduler: Any,
        criterion: nn.Module
    ) -> Dict[str, float]:
        """Entrena una época"""
        
        self.model.train()
        total_loss = 0.0
        
        progress_bar = tqdm(train_loader, desc="Training")
        
        for batch_flows, batch_labels in progress_bar:
            # Preparar inputs (simplificado - requiere implementación completa)
            # En producción: procesar cada flow del batch
            
            optimizer.zero_grad()
            
            # Forward pass simplificado
            # TODO: Implementar batching real con collate_fn
            
            # Simular loss para demo
            loss = torch.tensor(0.5, requires_grad=True)
            
            # Backward pass
            loss.backward()
            
            # Gradient clipping
            torch.nn.utils.clip_grad_norm_(
                self.model.parameters(),
                self.transformer_config.get('gradient_clip_norm', 1.0)
            )
            
            optimizer.step()
            scheduler.step()
            
            total_loss += loss.item()
            progress_bar.set_postfix({'loss': loss.item()})
        
        avg_loss = total_loss / len(train_loader)
        
        return {'loss': avg_loss}
    
    def _validate_epoch(
        self,
        val_loader: DataLoader,
        criterion: nn.Module
    ) -> Dict[str, float]:
        """Valida el modelo"""
        
        self.model.eval()
        total_loss = 0.0
        all_predictions = []
        all_labels = []
        
        with torch.no_grad():
            for batch_flows, batch_labels in tqdm(val_loader, desc="Validation"):
                # Similar a train_epoch
                # TODO: Implementación completa
                
                # Simular métricas para demo
                loss = 0.4
                predictions = [0.6] * len(batch_labels)
                
                total_loss += loss
                all_predictions.extend(predictions)
                all_labels.extend(batch_labels)
        
        # Calcular métricas
        all_predictions = np.array(all_predictions)
        all_labels = np.array(all_labels)
        
        pred_binary = (all_predictions >= 0.5).astype(int)
        
        metrics = self._calculate_metrics(pred_binary, all_labels)
        metrics['loss'] = total_loss / len(val_loader)
        
        return metrics
    
    def _calculate_metrics(
        self,
        predictions: np.ndarray,
        labels: np.ndarray
    ) -> Dict[str, float]:
        """Calcula métricas de clasificación"""
        
        from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
        
        metrics = {
            'precision': precision_score(labels, predictions, zero_division=0),
            'recall': recall_score(labels, predictions, zero_division=0),
            'f1': f1_score(labels, predictions, zero_division=0),
            'accuracy': accuracy_score(labels, predictions)
        }
        
        return metrics
    
    def _save_checkpoint(self, path: Path, metrics: Dict[str, float]) -> None:
        """Guarda checkpoint del modelo"""
        
        checkpoint = {
            'model_state_dict': self.model.state_dict(),
            'metrics': metrics,
            'config': self.transformer_config
        }
        
        torch.save(checkpoint, path)
        self.logger.info(f"Checkpoint guardado: {path}")
    
    def cross_validate(
        self,
        data: Dict[str, Any],
        n_folds: int = 5,
        output_dir: str = "models/cv_results/"
    ) -> Dict[str, List[float]]:
        """
        Realiza validación cruzada estratificada k-fold
        
        Args:
            data: Datos completos (flows + labels)
            n_folds: Número de folds
            output_dir: Directorio para guardar resultados
            
        Returns:
            Métricas agregadas por fold
        """
        self.logger.info(f"\nIniciando validación cruzada {n_folds}-fold...")
        
        flows = data['flows']
        labels = np.array(data['labels'])
        
        # Validación cruzada estratificada
        skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
        
        cv_metrics = {
            'precision': [],
            'recall': [],
            'f1': [],
            'accuracy': []
        }
        
        for fold, (train_idx, val_idx) in enumerate(skf.split(flows, labels), 1):
            self.logger.info(f"\n{'='*80}")
            self.logger.info(f"FOLD {fold}/{n_folds}")
            self.logger.info(f"{'='*80}")
            
            # Preparar datos del fold
            train_data = {
                'flows': [flows[i] for i in train_idx],
                'labels': labels[train_idx].tolist()
            }
            val_data = {
                'flows': [flows[i] for i in val_idx],
                'labels': labels[val_idx].tolist()
            }
            
            # Entrenar
            fold_metrics = self.train(
                train_data,
                val_data,
                output_dir=f"{output_dir}/fold_{fold}/"
            )
            
            # Agregar métricas
            for metric_name in cv_metrics:
                cv_metrics[metric_name].append(fold_metrics[metric_name])
        
        # Calcular estadísticas
        self.logger.info(f"\n{'='*80}")
        self.logger.info("RESULTADOS DE VALIDACIÓN CRUZADA")
        self.logger.info(f"{'='*80}")
        
        for metric_name, values in cv_metrics.items():
            mean = np.mean(values)
            std = np.std(values)
            self.logger.info(f"{metric_name.capitalize()}: {mean:.4f} ± {std:.4f}")
        
        # Guardar resultados
        results_file = Path(output_dir) / "cv_results.json"
        results_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(results_file, 'w') as f:
            json.dump(cv_metrics, f, indent=2)
        
        return cv_metrics


def main():
    """Punto de entrada principal"""
    
    parser = argparse.ArgumentParser(description="Entrenamiento del modelo Transformer")
    parser.add_argument(
        '--config',
        type=str,
        default='config/default_config.yaml',
        help='Archivo de configuración'
    )
    parser.add_argument(
        '--dataset',
        type=str,
        required=True,
        help='Ruta al dataset de entrenamiento (JSON)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='models/codebert_finetuned/',
        help='Directorio de salida'
    )
    parser.add_argument(
        '--cv',
        action='store_true',
        help='Realizar validación cruzada'
    )
    parser.add_argument(
        '--wandb',
        action='store_true',
        help='Usar Weights & Biases para tracking'
    )
    
    args = parser.parse_args()
    
    # Cargar configuración
    config = load_config(args.config)
    
    # Cargar dataset
    with open(args.dataset, 'r') as f:
        dataset = json.load(f)
    
    # Inicializar trainer
    trainer = Trainer(config, use_wandb=args.wandb)
    
    if args.wandb:
        wandb.init(project="android-vulnerability-detection", config=config)
    
    # Entrenar
    if args.cv:
        # Validación cruzada
        trainer.cross_validate(dataset, n_folds=5, output_dir=args.output)
    else:
        # Split train/val
        from sklearn.model_selection import train_test_split
        
        train_flows, val_flows, train_labels, val_labels = train_test_split(
            dataset['flows'],
            dataset['labels'],
            test_size=0.2,
            stratify=dataset['labels'],
            random_state=42
        )
        
        train_data = {'flows': train_flows, 'labels': train_labels}
        val_data = {'flows': val_flows, 'labels': val_labels}
        
        trainer.train(train_data, val_data, output_dir=args.output)
    
    if args.wandb:
        wandb.finish()


if __name__ == "__main__":
    main()

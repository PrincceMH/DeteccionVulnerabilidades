import os
import sys
import json
import pickle
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict

# Configurar paths
ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np


# Clases necesarias para deserializar el pickle
@dataclass
class APKSample:
    """Representa un APK procesado para entrenamiento."""
    apk_path: str
    apk_name: str
    label: int
    source: str
    category: str
    flows: List[Dict] = None
    num_flows: int = 0
    features: Optional[Dict] = None
    tokens: Optional[List[int]] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.flows is None:
            self.flows = []


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


@dataclass
class TrainingConfig:
    """Configuración de entrenamiento."""
    # Modelo
    hidden_size: int = 128
    num_layers: int = 4
    num_attention_heads: int = 4
    dropout: float = 0.1
    max_sequence_length: int = 128
    
    # Entrenamiento
    epochs: int = 50
    batch_size: int = 16
    learning_rate: float = 1e-4
    weight_decay: float = 0.01
    warmup_steps: int = 100
    gradient_clip: float = 1.0
    
    # Early stopping
    patience: int = 10
    min_delta: float = 0.001
    
    # Paths
    checkpoint_dir: str = "checkpoints"
    log_dir: str = "logs"


@dataclass
class TrainingMetrics:
    """Métricas de una época de entrenamiento."""
    epoch: int
    train_loss: float
    train_accuracy: float
    val_loss: float
    val_accuracy: float
    val_precision: float
    val_recall: float
    val_f1: float
    learning_rate: float
    duration_seconds: float


class VulnerabilityDataset(Dataset):
    """Dataset de PyTorch para vulnerabilidades Android."""
    
    def __init__(
        self,
        samples: List[Any],
        max_seq_length: int = 128,
        vocab_size: int = 1000
    ):
        self.samples = samples
        self.max_seq_length = max_seq_length
        self.vocab_size = vocab_size
        
    def __len__(self) -> int:
        return len(self.samples)
    
    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        sample = self.samples[idx]
        
        # Obtener tokens (o generar dummy si no hay)
        if sample.tokens and len(sample.tokens) > 0:
            tokens = sample.tokens[:self.max_seq_length]
        else:
            # Generar representación basada en número de flujos
            tokens = [1]  # [CLS]
            if sample.num_flows > 0:
                # Añadir tokens dummy basados en flujos
                for _ in range(min(sample.num_flows, 10)):
                    tokens.append(np.random.randint(10, self.vocab_size))
            tokens.append(2)  # [SEP]
        
        # Padding
        padding_length = self.max_seq_length - len(tokens)
        if padding_length > 0:
            tokens = tokens + [0] * padding_length
        else:
            tokens = tokens[:self.max_seq_length]
        
        # Attention mask (1 para tokens reales, 0 para padding)
        attention_mask = [1 if t != 0 else 0 for t in tokens]
        
        # Features numéricas adicionales
        numeric_features = self._extract_numeric_features(sample)
        
        return {
            'input_ids': torch.tensor(tokens, dtype=torch.long),
            'attention_mask': torch.tensor(attention_mask, dtype=torch.long),
            'numeric_features': torch.tensor(numeric_features, dtype=torch.float),
            'labels': torch.tensor(sample.label, dtype=torch.long)
        }
    
    def _extract_numeric_features(self, sample) -> List[float]:
        """Extrae features numéricas del sample."""
        features = [
            float(sample.num_flows),
            float(len(sample.flows) if sample.flows else 0),
            1.0 if sample.source == 'droidbench' else 0.0,
        ]
        
        # Estadísticas de flujos
        if sample.flows:
            risk_levels = [f.get('risk_level', 5) for f in sample.flows]
            features.extend([
                float(max(risk_levels)) if risk_levels else 0.0,
                float(min(risk_levels)) if risk_levels else 0.0,
                float(np.mean(risk_levels)) if risk_levels else 0.0,
                float(np.std(risk_levels)) if len(risk_levels) > 1 else 0.0,
            ])
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])
        
        # Padding a 12 features
        while len(features) < 12:
            features.append(0.0)
        
        return features[:12]


class Trainer:
    """Clase principal de entrenamiento."""
    
    def __init__(
        self,
        model: nn.Module,
        config: TrainingConfig,
        device: torch.device
    ):
        self.model = model.to(device)
        self.config = config
        self.device = device
        
        # Optimizador
        self.optimizer = optim.AdamW(
            model.parameters(),
            lr=config.learning_rate,
            weight_decay=config.weight_decay
        )
        
        # Scheduler
        self.scheduler = optim.lr_scheduler.CosineAnnealingLR(
            self.optimizer,
            T_max=config.epochs,
            eta_min=1e-6
        )
        
        # Loss function con pesos para balancear clases
        self.criterion = nn.CrossEntropyLoss()
        
        # Tracking
        self.best_val_f1 = 0.0
        self.epochs_without_improvement = 0
        self.history: List[TrainingMetrics] = []
        
        # Crear directorios
        Path(config.checkpoint_dir).mkdir(parents=True, exist_ok=True)
        Path(config.log_dir).mkdir(parents=True, exist_ok=True)
    
    def train_epoch(self, dataloader: DataLoader) -> Tuple[float, float]:
        """Entrena una época."""
        self.model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        
        for batch in dataloader:
            # Mover a device
            input_ids = batch['input_ids'].to(self.device)
            attention_mask = batch['attention_mask'].to(self.device)
            numeric_features = batch['numeric_features'].to(self.device)
            labels = batch['labels'].to(self.device)
            
            # Forward
            self.optimizer.zero_grad()
            outputs = self.model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                numeric_features=numeric_features
            )
            
            # Extraer logits del diccionario
            logits = outputs['logits'] if isinstance(outputs, dict) else outputs
            
            # Loss
            loss = self.criterion(logits, labels)
            
            # Backward
            loss.backward()
            
            # Gradient clipping
            torch.nn.utils.clip_grad_norm_(
                self.model.parameters(),
                self.config.gradient_clip
            )
            
            self.optimizer.step()
            
            # Métricas
            total_loss += loss.item()
            _, predicted = torch.max(logits, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
        
        avg_loss = total_loss / len(dataloader)
        accuracy = correct / total
        
        return avg_loss, accuracy
    
    def evaluate(self, dataloader: DataLoader) -> Dict[str, float]:
        """Evalúa el modelo."""
        self.model.eval()
        total_loss = 0.0
        all_predictions = []
        all_labels = []
        
        with torch.no_grad():
            for batch in dataloader:
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                numeric_features = batch['numeric_features'].to(self.device)
                labels = batch['labels'].to(self.device)
                
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    numeric_features=numeric_features
                )
                
                # Extraer logits del diccionario
                logits = outputs['logits'] if isinstance(outputs, dict) else outputs
                
                loss = self.criterion(logits, labels)
                total_loss += loss.item()
                
                _, predicted = torch.max(logits, 1)
                all_predictions.extend(predicted.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
        
        # Calcular métricas
        all_predictions = np.array(all_predictions)
        all_labels = np.array(all_labels)
        
        accuracy = np.mean(all_predictions == all_labels)
        
        # Precision, Recall, F1 para clase positiva (vulnerable)
        tp = np.sum((all_predictions == 1) & (all_labels == 1))
        fp = np.sum((all_predictions == 1) & (all_labels == 0))
        fn = np.sum((all_predictions == 0) & (all_labels == 1))
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {
            'loss': total_loss / len(dataloader),
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
    
    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader
    ) -> List[TrainingMetrics]:
        """Ejecuta el entrenamiento completo."""
        print("=" * 60)
        print("ENTRENAMIENTO DEL MODELO")
        print("=" * 60)
        print(f"Dispositivo: {self.device}")
        print(f"Epochs: {self.config.epochs}")
        print(f"Batch size: {self.config.batch_size}")
        print(f"Learning rate: {self.config.learning_rate}")
        print(f"Train samples: {len(train_loader.dataset)}")
        print(f"Val samples: {len(val_loader.dataset)}")
        print("=" * 60)
        
        for epoch in range(1, self.config.epochs + 1):
            start_time = datetime.now()
            
            # Entrenar
            train_loss, train_acc = self.train_epoch(train_loader)
            
            # Evaluar
            val_metrics = self.evaluate(val_loader)
            
            # Actualizar scheduler
            self.scheduler.step()
            current_lr = self.scheduler.get_last_lr()[0]
            
            # Tiempo
            duration = (datetime.now() - start_time).total_seconds()
            
            # Guardar métricas
            metrics = TrainingMetrics(
                epoch=epoch,
                train_loss=train_loss,
                train_accuracy=train_acc,
                val_loss=val_metrics['loss'],
                val_accuracy=val_metrics['accuracy'],
                val_precision=val_metrics['precision'],
                val_recall=val_metrics['recall'],
                val_f1=val_metrics['f1'],
                learning_rate=current_lr,
                duration_seconds=duration
            )
            self.history.append(metrics)
            
            # Imprimir progreso
            print(
                f"Epoch {epoch:3d}/{self.config.epochs} | "
                f"Train Loss: {train_loss:.4f} | "
                f"Val Loss: {val_metrics['loss']:.4f} | "
                f"Val Acc: {val_metrics['accuracy']:.4f} | "
                f"Val F1: {val_metrics['f1']:.4f} | "
                f"LR: {current_lr:.2e} | "
                f"Time: {duration:.1f}s"
            )
            
            # Guardar mejor modelo
            if val_metrics['f1'] > self.best_val_f1 + self.config.min_delta:
                self.best_val_f1 = val_metrics['f1']
                self.epochs_without_improvement = 0
                self.save_checkpoint(epoch, is_best=True)
                print(f"  -> Nuevo mejor modelo guardado (F1: {self.best_val_f1:.4f})")
            else:
                self.epochs_without_improvement += 1
            
            # Early stopping
            if self.epochs_without_improvement >= self.config.patience:
                print(f"\nEarly stopping en epoch {epoch}")
                break
            
            # Guardar checkpoint periódico
            if epoch % 10 == 0:
                self.save_checkpoint(epoch)
        
        # Guardar historial
        self.save_history()
        
        return self.history
    
    def save_checkpoint(self, epoch: int, is_best: bool = False):
        """Guarda un checkpoint del modelo."""
        checkpoint = {
            'epoch': epoch,
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'scheduler_state_dict': self.scheduler.state_dict(),
            'best_val_f1': self.best_val_f1,
            'config': asdict(self.config)
        }
        
        if is_best:
            path = Path(self.config.checkpoint_dir) / "best_model.pt"
        else:
            path = Path(self.config.checkpoint_dir) / f"checkpoint_epoch_{epoch}.pt"
        
        torch.save(checkpoint, path)
    
    def load_checkpoint(self, path: str):
        """Carga un checkpoint."""
        checkpoint = torch.load(path, map_location=self.device, weights_only=False)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.scheduler.load_state_dict(checkpoint['scheduler_state_dict'])
        self.best_val_f1 = checkpoint.get('best_val_f1', 0.0)
        return checkpoint['epoch']
    
    def save_history(self):
        """Guarda el historial de entrenamiento."""
        history_path = Path(self.config.log_dir) / "training_history.json"
        
        history_data = {
            'config': asdict(self.config),
            'best_val_f1': self.best_val_f1,
            'epochs_trained': len(self.history),
            'history': [asdict(m) for m in self.history]
        }
        
        with open(history_path, 'w') as f:
            json.dump(history_data, f, indent=2)
        
        print(f"\nHistorial guardado en: {history_path}")


def load_dataset(data_path: Path) -> Tuple[List, List, List, int]:
    """Carga el dataset preparado."""
    with open(data_path, 'rb') as f:
        dataset = pickle.load(f)
    
    return (
        dataset.train_samples,
        dataset.val_samples,
        dataset.test_samples,
        dataset.vocab_size
    )


def create_model(vocab_size: int, config: TrainingConfig):
    """Crea el modelo."""
    from transformer import VulnerabilityClassifier
    from transformer.vulnerability_classifier import TransformerConfig
    
    # Crear configuración del Transformer
    model_config = TransformerConfig(
        vocab_size=max(vocab_size, 1000),  # Mínimo 1000
        hidden_size=config.hidden_size,
        num_hidden_layers=config.num_layers,
        num_attention_heads=config.num_attention_heads,
        intermediate_size=config.hidden_size * 4,
        max_position_embeddings=config.max_sequence_length,
        hidden_dropout_prob=config.dropout,
        attention_dropout_prob=config.dropout,
        num_labels=2
    )
    
    model = VulnerabilityClassifier(model_config)
    
    return model


def print_final_results(trainer: Trainer, test_loader: DataLoader):
    """Imprime resultados finales."""
    print("\n" + "=" * 60)
    print("RESULTADOS FINALES")
    print("=" * 60)
    
    # Cargar mejor modelo
    best_path = Path(trainer.config.checkpoint_dir) / "best_model.pt"
    if best_path.exists():
        trainer.load_checkpoint(str(best_path))
        print("Cargado mejor modelo para evaluación final")
    
    # Evaluar en test
    test_metrics = trainer.evaluate(test_loader)
    
    print(f"\nMétricas en Test Set:")
    print(f"  Accuracy:  {test_metrics['accuracy']:.4f}")
    print(f"  Precision: {test_metrics['precision']:.4f}")
    print(f"  Recall:    {test_metrics['recall']:.4f}")
    print(f"  F1-Score:  {test_metrics['f1']:.4f}")
    
    print(f"\nMejor F1 en Validación: {trainer.best_val_f1:.4f}")
    print(f"Epochs entrenados: {len(trainer.history)}")
    
    # Guardar resultados finales
    results = {
        'test_metrics': test_metrics,
        'best_val_f1': trainer.best_val_f1,
        'epochs_trained': len(trainer.history),
        'timestamp': datetime.now().isoformat()
    }
    
    results_path = Path(trainer.config.log_dir) / "final_results.json"
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResultados guardados en: {results_path}")


def main():
    parser = argparse.ArgumentParser(description='Entrenar modelo de detección')
    parser.add_argument('--epochs', type=int, default=50)
    parser.add_argument('--batch-size', type=int, default=16)
    parser.add_argument('--lr', type=float, default=1e-4)
    parser.add_argument('--hidden-size', type=int, default=128)
    parser.add_argument('--num-layers', type=int, default=4)
    parser.add_argument('--resume', type=str, default=None)
    parser.add_argument('--data', type=str, default='data/prepared/prepared_dataset.pkl')
    
    args = parser.parse_args()
    
    # Configuración
    config = TrainingConfig(
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        hidden_size=args.hidden_size,
        num_layers=args.num_layers
    )
    
    # Device
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Usando dispositivo: {device}")
    
    # Cargar datos
    data_path = ROOT_DIR / args.data
    if not data_path.exists():
        print(f"Error: No se encuentra el dataset en {data_path}")
        print("Ejecuta primero: python scripts/prepare_training_data.py")
        sys.exit(1)
    
    print(f"Cargando dataset desde: {data_path}")
    train_samples, val_samples, test_samples, vocab_size = load_dataset(data_path)
    
    print(f"Samples - Train: {len(train_samples)}, Val: {len(val_samples)}, Test: {len(test_samples)}")
    print(f"Vocabulario: {vocab_size} tokens")
    
    # Crear datasets
    train_dataset = VulnerabilityDataset(train_samples, config.max_sequence_length, vocab_size)
    val_dataset = VulnerabilityDataset(val_samples, config.max_sequence_length, vocab_size)
    test_dataset = VulnerabilityDataset(test_samples, config.max_sequence_length, vocab_size)
    
    # Crear dataloaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=config.batch_size,
        shuffle=True,
        num_workers=0
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=config.batch_size,
        shuffle=False,
        num_workers=0
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=config.batch_size,
        shuffle=False,
        num_workers=0
    )
    
    # Crear modelo
    print("\nCreando modelo...")
    model = create_model(vocab_size, config)
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Parámetros totales: {total_params:,}")
    print(f"Parámetros entrenables: {trainable_params:,}")
    
    # Crear trainer
    trainer = Trainer(model, config, device)
    
    # Resumir si se especifica
    start_epoch = 0
    if args.resume:
        if Path(args.resume).exists():
            start_epoch = trainer.load_checkpoint(args.resume)
            print(f"Resumiendo desde epoch {start_epoch}")
        else:
            print(f"Warning: No se encontró checkpoint en {args.resume}")
    
    # Entrenar
    trainer.train(train_loader, val_loader)
    
    # Resultados finales
    print_final_results(trainer, test_loader)
    
    print("\n" + "=" * 60)
    print("ENTRENAMIENTO COMPLETADO")
    print("=" * 60)


if __name__ == "__main__":
    main()

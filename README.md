# Framework de Detección Automatizada de Vulnerabilidades en Android

## Descripción
Framework híbrido para detección de vulnerabilidades en aplicaciones Android mediante análisis estático de flujos de información y modelos Transformer.

## Arquitectura del Sistema

```
├── modules/
│   ├── preprocessing/        # Módulo 1: Preprocesamiento APK
│   ├── taint_analysis/       # Módulo 2: Análisis Taint Especializado
│   ├── transformer_model/    # Módulo 3: Clasificación Transformer
│   └── dynamic_validation/   # Módulo 4: Validación Dinámica Selectiva
├── datasets/
│   ├── droidbench/          # Suite de pruebas DroidBench
│   ├── ghera/               # Aplicaciones Ghera
│   └── androzoo/            # Subset AndroZoo
├── models/
│   ├── codebert_finetuned/  # Modelo CodeBERT fine-tuneado
│   └── checkpoints/         # Checkpoints de entrenamiento
├── results/
│   ├── experiments/         # Resultados experimentales
│   ├── visualizations/      # Gráficos y visualizaciones
│   └── reports/             # Reportes de vulnerabilidades
├── config/                  # Archivos de configuración
├── scripts/                 # Scripts de utilidad
└── tests/                   # Pruebas unitarias

```

## Stack Tecnológico

### Backend
- Python 3.9+
- PyTorch 1.13+
- Transformers (Hugging Face) 4.21+

### Análisis Estático
- Soot Framework v4.3.0 (Java)
- Jadx decompiler v1.4.7
- FlowDroid

### Modelo Base
- CodeBERT (`microsoft/codebert-base`)

### Instrumentación
- Frida Framework v16.0+
- Android Emulators (API 28-33)

### Bases de Datos
- PostgreSQL 14+
- Redis 7+

## Instalación

### Requisitos de Hardware
- **CPU:** 16+ cores Intel Xeon o AMD EPYC
- **RAM:** 64GB
- **GPU:** NVIDIA V100/A100 (32GB VRAM)
- **Storage:** 2TB NVMe SSD

### Instalación de Dependencias

```bash
# Crear entorno virtual
python -m venv venv
.\venv\Scripts\activate  # Windows

# Instalar dependencias Python
pip install -r requirements.txt

# Instalar herramientas Java (Soot, Jadx)
# Ver instrucciones en docs/installation.md
```

## Uso

### 1. Análisis de APK Individual

```bash
python main.py analyze --apk path/to/app.apk --output results/
```

### 2. Análisis Batch

```bash
python main.py batch --input datasets/apks/ --output results/batch/
```

### 3. Entrenamiento del Modelo

```bash
python scripts/train_model.py --config config/training_config.yaml
```

### 4. Evaluación

```bash
python scripts/evaluate.py --dataset droidbench --model models/codebert_finetuned/
```

## Módulos

### 1. Preprocesamiento APK
- Descompilación con Jadx
- Conversión a Jimple (Soot)
- Extracción de AndroidManifest.xml
- Generación de CFGs

### 2. Análisis Taint Especializado
- Flow-sensitive analysis
- Sources/Sinks Android-específicos
- Grafos etiquetados de flujos
- Análisis inter-componente

### 3. Modelo Transformer
- CodeBERT fine-tuneado
- Embeddings especializados Android
- Scoring de criticidad [0,1]
- Clasificación contextual

### 4. Validación Dinámica Selectiva
- Instrumentación Frida
- Taint propagation testing
- Generación automática de PoCs
- Activación inteligente (score > 0.75)

## Resultados Esperados

| Métrica | Objetivo |
|---------|----------|
| Precisión | 85-89% |
| Recall | 82-86% |
| F1-Score | 84-87% |
| Tasa FP | 20-25% |

## Datasets

### DroidBench
- 100+ aplicaciones micro con vulnerabilidades conocidas
- Ground truth preciso

### Ghera
- 61 aplicaciones con vulnerabilidades reales
- Casos del mundo real

### AndroZoo
- Subset curado de aplicaciones reales
- Casos negativos para especificidad

## Publicaciones

- Tesis de grado: "Detección Automatizada de Vulnerabilidades en Aplicaciones Android mediante Análisis Estático de Flujos de Información y Modelos Transformer"

## Licencia

MIT License (Investigación Académica)

## Autor

[Tu Nombre]
Universidad Nacional de San Agustín de Arequipa (UNSA)
2025

## Referencias

Ver capítulo de Marco Teórico en la tesis para referencias completas.

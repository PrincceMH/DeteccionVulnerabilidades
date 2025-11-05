"""
Utilidad para cargar archivos de configuración YAML
"""

import yaml
from pathlib import Path
from typing import Dict, Any
import os


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Carga configuración desde archivo YAML con soporte para variables de entorno
    
    Args:
        config_path: Ruta al archivo YAML
        
    Returns:
        Diccionario con configuración
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Archivo de configuración no encontrado: {config_path}")
    
    with open(config_file, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    # Reemplazar variables de entorno
    config = _replace_env_variables(config)
    
    return config


def _replace_env_variables(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Reemplaza variables de entorno en la configuración (formato: ${VAR_NAME})
    """
    if isinstance(config, dict):
        return {k: _replace_env_variables(v) for k, v in config.items()}
    elif isinstance(config, list):
        return [_replace_env_variables(item) for item in config]
    elif isinstance(config, str) and config.startswith('${') and config.endswith('}'):
        var_name = config[2:-1]
        return os.getenv(var_name, config)
    else:
        return config

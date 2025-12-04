import os
import sys
import json
import time
import argparse
import hashlib
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from urllib.request import urlopen, urlretrieve, Request
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuracion
FDROID_INDEX_URL = "https://f-droid.org/repo/index-v1.json"
FDROID_REPO_URL = "https://f-droid.org/repo"
OUTPUT_DIR = Path(__file__).parent.parent / "datasets" / "benign" / "fdroid"


@dataclass
class AppInfo:
    """Informacion de una aplicacion de F-Droid."""
    package_name: str
    name: str
    version: str
    apk_name: str
    size: int
    hash_value: str
    categories: List[str]


def download_index() -> Dict:
    """Descarga el indice de F-Droid."""
    print("Descargando indice de F-Droid...")
    
    try:
        request = Request(
            FDROID_INDEX_URL,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urlopen(request, timeout=60) as response:
            data = json.loads(response.read().decode('utf-8'))
            print(f"Indice descargado: {len(data.get('apps', []))} aplicaciones disponibles")
            return data
    except Exception as e:
        print(f"Error descargando indice: {e}")
        return {}


def parse_apps(index_data: Dict, max_size_mb: float = 50.0) -> List[AppInfo]:
    """
    Parsea las aplicaciones del indice.
    
    Args:
        index_data: Datos del indice de F-Droid
        max_size_mb: Tamano maximo de APK en MB
    
    Returns:
        Lista de AppInfo con aplicaciones validas
    """
    apps = []
    packages = index_data.get('packages', {})
    app_metadata = {app['packageName']: app for app in index_data.get('apps', [])}
    
    max_size_bytes = max_size_mb * 1024 * 1024
    
    for package_name, versions in packages.items():
        if not versions:
            continue
            
        # Tomar la version mas reciente
        latest = versions[0]
        
        # Filtrar por tamano
        size = latest.get('size', 0)
        if size > max_size_bytes or size == 0:
            continue
        
        # Obtener metadata
        metadata = app_metadata.get(package_name, {})
        
        app = AppInfo(
            package_name=package_name,
            name=metadata.get('name', package_name),
            version=latest.get('versionName', 'unknown'),
            apk_name=latest.get('apkName', ''),
            size=size,
            hash_value=latest.get('hash', ''),
            categories=metadata.get('categories', [])
        )
        
        if app.apk_name:
            apps.append(app)
    
    return apps


def download_apk(app: AppInfo, output_dir: Path) -> bool:
    """
    Descarga un APK de F-Droid.
    
    Args:
        app: Informacion de la aplicacion
        output_dir: Directorio de salida
    
    Returns:
        True si la descarga fue exitosa
    """
    output_path = output_dir / app.apk_name
    
    # Verificar si ya existe
    if output_path.exists():
        print(f"  [SKIP] {app.name} - ya existe")
        return True
    
    url = f"{FDROID_REPO_URL}/{app.apk_name}"
    
    try:
        request = Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        
        with urlopen(request, timeout=120) as response:
            data = response.read()
            
            # Verificar hash si esta disponible
            if app.hash_value:
                actual_hash = hashlib.sha256(data).hexdigest()
                if actual_hash.lower() != app.hash_value.lower():
                    print(f"  [ERROR] {app.name} - hash no coincide")
                    return False
            
            # Guardar archivo
            with open(output_path, 'wb') as f:
                f.write(data)
            
            size_mb = len(data) / (1024 * 1024)
            print(f"  [OK] {app.name} ({size_mb:.1f} MB)")
            return True
            
    except HTTPError as e:
        print(f"  [ERROR] {app.name} - HTTP {e.code}")
        return False
    except URLError as e:
        print(f"  [ERROR] {app.name} - {e.reason}")
        return False
    except Exception as e:
        print(f"  [ERROR] {app.name} - {e}")
        return False


def download_batch(
    apps: List[AppInfo],
    output_dir: Path,
    count: int,
    categories: Optional[List[str]] = None
) -> int:
    """
    Descarga un lote de APKs.
    
    Args:
        apps: Lista de aplicaciones disponibles
        output_dir: Directorio de salida
        count: Numero de APKs a descargar
        categories: Filtrar por categorias (opcional)
    
    Returns:
        Numero de APKs descargados exitosamente
    """
    # Filtrar por categoria si se especifica
    if categories:
        categories_lower = [c.lower() for c in categories]
        apps = [
            app for app in apps
            if any(c.lower() in categories_lower for c in app.categories)
        ]
        print(f"Aplicaciones en categorias {categories}: {len(apps)}")
    
    # Ordenar por tamano (primero los mas pequenos para descarga rapida)
    apps = sorted(apps, key=lambda x: x.size)[:count]
    
    print(f"\nDescargando {len(apps)} APKs a {output_dir}")
    print("-" * 60)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    successful = 0
    for i, app in enumerate(apps, 1):
        print(f"[{i}/{len(apps)}] Descargando {app.name}...")
        if download_apk(app, output_dir):
            successful += 1
        
        # Pausa para no sobrecargar el servidor
        time.sleep(0.5)
    
    return successful


def create_metadata(apps: List[AppInfo], output_dir: Path) -> None:
    """
    Crea archivo de metadata para las apps descargadas.
    """
    metadata_path = output_dir / "metadata.json"
    
    # Solo incluir apps que fueron descargadas
    downloaded_apps = []
    for app in apps:
        apk_path = output_dir / app.apk_name
        if apk_path.exists():
            downloaded_apps.append({
                'package_name': app.package_name,
                'name': app.name,
                'version': app.version,
                'apk_name': app.apk_name,
                'size': app.size,
                'categories': app.categories,
                'label': 'benign',
                'source': 'fdroid'
            })
    
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump({
            'total_apps': len(downloaded_apps),
            'source': 'F-Droid',
            'label': 'benign',
            'apps': downloaded_apps
        }, f, indent=2, ensure_ascii=False)
    
    print(f"\nMetadata guardada en: {metadata_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Descargar APKs benignos de F-Droid'
    )
    parser.add_argument(
        '--count', '-n',
        type=int,
        default=50,
        help='Numero de APKs a descargar (default: 50)'
    )
    parser.add_argument(
        '--max-size',
        type=float,
        default=30.0,
        help='Tamano maximo de APK en MB (default: 30)'
    )
    parser.add_argument(
        '--category', '-c',
        type=str,
        nargs='*',
        help='Filtrar por categorias (ej: games, productivity)'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        default=str(OUTPUT_DIR),
        help='Directorio de salida'
    )
    
    args = parser.parse_args()
    output_dir = Path(args.output)
    
    print("=" * 60)
    print("DESCARGA DE APKS BENIGNOS - F-DROID")
    print("=" * 60)
    print(f"APKs a descargar: {args.count}")
    print(f"Tamano maximo: {args.max_size} MB")
    print(f"Directorio: {output_dir}")
    if args.category:
        print(f"Categorias: {args.category}")
    print("=" * 60)
    
    # Descargar indice
    index_data = download_index()
    if not index_data:
        print("Error: No se pudo obtener el indice de F-Droid")
        sys.exit(1)
    
    # Parsear aplicaciones
    apps = parse_apps(index_data, max_size_mb=args.max_size)
    print(f"Aplicaciones validas (< {args.max_size}MB): {len(apps)}")
    
    # Descargar APKs
    successful = download_batch(
        apps=apps,
        output_dir=output_dir,
        count=args.count,
        categories=args.category
    )
    
    # Crear metadata
    create_metadata(apps, output_dir)
    
    # Resumen
    print("\n" + "=" * 60)
    print("RESUMEN")
    print("=" * 60)
    print(f"APKs descargados: {successful}/{args.count}")
    print(f"Directorio: {output_dir}")
    
    # Contar archivos
    apk_files = list(output_dir.glob("*.apk"))
    print(f"Total APKs en directorio: {len(apk_files)}")
    
    total_size = sum(f.stat().st_size for f in apk_files) / (1024 * 1024)
    print(f"Tamano total: {total_size:.1f} MB")


if __name__ == "__main__":
    main()

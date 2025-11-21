from pathlib import Path
from src.preprocessing.apk_loader import ApkLoader
from src.preprocessing.decompiler import ApkDecompiler
from src.preprocessing.metadata_extractor import MetadataExtractor


def main():
    dataset_path = Path("datasets/droidbench/datasets/droidbench/DroidBench/apk")
    output_dir = Path("output/decompiled")
    
    loader = ApkLoader(dataset_path)
    decompiler = ApkDecompiler(output_dir)
    extractor = MetadataExtractor(decompiler)
    
    apks = loader.load_dataset()
    
    print(f"Probando extracción completa de metadata con 2 APKs...\n")
    
    for apk_info in apks[:2]:
        print(f"{'='*60}")
        print(f"APK: {apk_info.name}")
        print(f"Categoría: {apk_info.category}")
        print(f"{'='*60}")
        
        try:
            metadata = extractor.extract(apk_info.path)
            
            print(f"\n[Información Básica]")
            print(f"  Package: {metadata.package_name}")
            print(f"  Version: {metadata.version_name} ({metadata.version_code})")
            print(f"  SDK: {metadata.min_sdk} → {metadata.target_sdk}")
            print(f"  Tamaño: {metadata.file_size / 1024:.2f} KB")
            print(f"  DEX files: {metadata.dex_count}")
            
            print(f"\n[Permisos]")
            print(f"  Total: {len(metadata.permissions)}")
            print(f"  Peligrosos: {len(metadata.dangerous_permissions)}")
            if metadata.dangerous_permissions:
                for perm in metadata.dangerous_permissions:
                    print(f"    - {perm}")
            
            print(f"\n[Componentes]")
            print(f"  Activities: {len(metadata.activities)} (Exportadas: {sum(1 for a in metadata.exported_activities if a.is_exported)})")
            print(f"  Services: {len(metadata.services)} (Exportadas: {sum(1 for s in metadata.exported_services if s.is_exported)})")
            print(f"  Receivers: {len(metadata.receivers)} (Exportados: {sum(1 for r in metadata.exported_receivers if r.is_exported)})")
            print(f"  Providers: {len(metadata.providers)} (Exportados: {sum(1 for p in metadata.exported_providers if p.is_exported)})")
            
            if any(a.is_exported for a in metadata.exported_activities):
                print(f"\n[Componentes Exportados - RIESGO]")
                for activity in metadata.exported_activities:
                    if activity.is_exported:
                        print(f"  Activity: {activity.name}")
                        if activity.intent_filters:
                            print(f"    Intent Filters: {', '.join(activity.intent_filters)}")
            
            print(f"\n[Flags de Seguridad]")
            print(f"  Debuggable: {'⚠️ SÍ' if metadata.security_flags.debuggable else '✓ NO'}")
            print(f"  Allow Backup: {'⚠️ SÍ' if metadata.security_flags.allow_backup else '✓ NO'}")
            print(f"  Cleartext Traffic: {'⚠️ SÍ' if metadata.security_flags.uses_cleartext_traffic else '✓ NO'}")
            print(f"  Test Only: {'⚠️ SÍ' if metadata.security_flags.test_only else '✓ NO'}")
            
            if metadata.native_libraries:
                print(f"\n[Librerías Nativas]")
                print(f"  Total: {len(metadata.native_libraries)}")
                for lib in metadata.native_libraries[:3]:
                    print(f"    - {lib}")
                if len(metadata.native_libraries) > 3:
                    print(f"    ... y {len(metadata.native_libraries) - 3} más")
            
            if metadata.certificate_info:
                print(f"\n[Certificado]")
                print(f"  Issuer: {metadata.certificate_info['issuer'][:50]}...")
                print(f"  Subject: {metadata.certificate_info['subject'][:50]}...")
            
            print()
            
        except Exception as e:
            print(f"  Error: {e}\n")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()

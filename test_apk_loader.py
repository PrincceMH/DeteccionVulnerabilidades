from pathlib import Path
from src.preprocessing.apk_loader import ApkLoader


def main():
    dataset_path = Path("datasets/droidbench/datasets/droidbench/DroidBench/apk")
    
    loader = ApkLoader(dataset_path)
    apks = loader.load_dataset()
    
    print(f"Total APKs encontrados: {len(apks)}")
    print("\nCategorías:")
    for category in sorted(loader.get_all_categories()):
        count = len(loader.get_apks_by_category(category))
        print(f"  - {category}: {count} APKs")
    
    print("\nPrimeros 5 APKs:")
    for apk in apks[:5]:
        print(f"  {apk.name} ({apk.category}) - {apk.size / 1024:.2f} KB")


if __name__ == "__main__":
    main()

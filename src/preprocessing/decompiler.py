from pathlib import Path
from typing import Optional, List
from androguard.core.apk import APK
from androguard.core.dex import DEX
import zipfile


class ApkDecompiler:
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def load_apk(self, apk_path: Path) -> APK:
        return APK(str(apk_path))
    
    def extract_dex_files(self, apk_path: Path) -> List[Path]:
        output_path = self.output_dir / apk_path.stem
        output_path.mkdir(parents=True, exist_ok=True)
        
        dex_files = []
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            for file in zip_ref.namelist():
                if file.endswith('.dex'):
                    dex_output = output_path / file
                    with open(dex_output, 'wb') as dex_file:
                        dex_file.write(zip_ref.read(file))
                    dex_files.append(dex_output)
        
        return dex_files
    
    def get_dex_objects(self, apk: APK) -> List[DEX]:
        dex_files = []
        for dex in apk.get_all_dex():
            dex_files.append(dex)
        return dex_files
    
    def extract_manifest(self, apk: APK) -> str:
        return apk.get_android_manifest_xml().toxml()
    
    def get_package_name(self, apk: APK) -> str:
        return apk.get_package()
    
    def get_permissions(self, apk: APK) -> List[str]:
        return apk.get_permissions()
    
    def get_activities(self, apk: APK) -> List[str]:
        return apk.get_activities()
    
    def get_services(self, apk: APK) -> List[str]:
        return apk.get_services()
    
    def get_receivers(self, apk: APK) -> List[str]:
        return apk.get_receivers()
    
    def get_providers(self, apk: APK) -> List[str]:
        return apk.get_providers()

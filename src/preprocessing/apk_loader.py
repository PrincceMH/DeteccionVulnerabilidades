from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

#extraccion apk 1.1
@dataclass
class ApkInfo:
    name: str
    path: Path
    category: str
    size: int


class ApkLoader:
    
    def __init__(self, dataset_path: Path):
        self.dataset_path = dataset_path
        self.apks: List[ApkInfo] = []
    
    def load_dataset(self) -> List[ApkInfo]:
        apk_files = list(self.dataset_path.rglob("*.apk"))
        
        for apk_file in apk_files:
            category = self._extract_category(apk_file)
            apk_info = ApkInfo(
                name=apk_file.stem,
                path=apk_file,
                category=category,
                size=apk_file.stat().st_size
            )
            self.apks.append(apk_info)
        
        return self.apks
    
    def _extract_category(self, apk_path: Path) -> str:
        parts = apk_path.parts
        for part in reversed(parts):
            if part != "apk" and not part.endswith(".apk"):
                return part
        return "Unknown"
    
    def get_apk_by_name(self, name: str) -> Optional[ApkInfo]:
        for apk in self.apks:
            if apk.name == name:
                return apk
        return None
    
    def get_apks_by_category(self, category: str) -> List[ApkInfo]:
        return [apk for apk in self.apks if apk.category == category]
    
    def get_all_categories(self) -> List[str]:
        return list(set(apk.category for apk in self.apks))

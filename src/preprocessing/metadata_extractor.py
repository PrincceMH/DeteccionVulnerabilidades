from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from androguard.core.apk import APK
from src.preprocessing.decompiler import ApkDecompiler


@dataclass
class ComponentInfo:
    name: str
    is_exported: bool
    intent_filters: List[str] = field(default_factory=list)


@dataclass
class SecurityFlags:
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: bool = True
    test_only: bool = False


@dataclass
class ApkMetadata:
    package_name: str
    version_code: Optional[str] = None
    version_name: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    main_activity: Optional[str] = None
    file_size: int = 0
    dex_count: int = 0
    exported_activities: List[ComponentInfo] = field(default_factory=list)
    exported_services: List[ComponentInfo] = field(default_factory=list)
    exported_receivers: List[ComponentInfo] = field(default_factory=list)
    exported_providers: List[ComponentInfo] = field(default_factory=list)
    security_flags: SecurityFlags = field(default_factory=SecurityFlags)
    dangerous_permissions: List[str] = field(default_factory=list)
    native_libraries: List[str] = field(default_factory=list)
    certificate_info: Optional[Dict] = None


class MetadataExtractor:
    
    def __init__(self, decompiler: ApkDecompiler):
        self.decompiler = decompiler
    
    def extract(self, apk_path: Path) -> ApkMetadata:
        apk = self.decompiler.load_apk(apk_path)
        
        permissions = apk.get_permissions()
        
        metadata = ApkMetadata(
            package_name=apk.get_package(),
            version_code=apk.get_androidversion_code(),
            version_name=apk.get_androidversion_name(),
            min_sdk=self._get_min_sdk(apk),
            target_sdk=self._get_target_sdk(apk),
            permissions=permissions,
            activities=apk.get_activities(),
            services=apk.get_services(),
            receivers=apk.get_receivers(),
            providers=apk.get_providers(),
            main_activity=apk.get_main_activity(),
            file_size=apk_path.stat().st_size,
            dex_count=len(list(apk.get_all_dex())),
            exported_activities=self._get_exported_components(apk, 'activity'),
            exported_services=self._get_exported_components(apk, 'service'),
            exported_receivers=self._get_exported_components(apk, 'receiver'),
            exported_providers=self._get_exported_components(apk, 'provider'),
            security_flags=self._extract_security_flags(apk),
            dangerous_permissions=self._filter_dangerous_permissions(permissions),
            native_libraries=self._extract_native_libraries(apk),
            certificate_info=self._extract_certificate_info(apk)
        )
        
        return metadata
    
    def _get_min_sdk(self, apk: APK) -> Optional[int]:
        try:
            return int(apk.get_min_sdk_version())
        except (ValueError, TypeError):
            return None
    
    def _get_target_sdk(self, apk: APK) -> Optional[int]:
        try:
            return int(apk.get_target_sdk_version())
        except (ValueError, TypeError):
            return None
    
    def _get_exported_components(self, apk: APK, component_type: str) -> List[ComponentInfo]:
        components = []
        
        if component_type == 'activity':
            component_list = apk.get_activities()
        elif component_type == 'service':
            component_list = apk.get_services()
        elif component_type == 'receiver':
            component_list = apk.get_receivers()
        elif component_type == 'provider':
            component_list = apk.get_providers()
        else:
            return components
        
        for component in component_list:
            is_exported = self._is_component_exported(apk, component, component_type)
            intent_filters = self._get_intent_filters(apk, component, component_type)
            
            components.append(ComponentInfo(
                name=component,
                is_exported=is_exported,
                intent_filters=intent_filters
            ))
        
        return components
    
    def _is_component_exported(self, apk: APK, component_name: str, component_type: str) -> bool:
        manifest = apk.get_android_manifest_xml()
        application = manifest.find('.//application')
        
        if application is None:
            return False
        
        component_tag = application.find(f'.//{component_type}[@{{http://schemas.android.com/apk/res/android}}name="{component_name}"]')
        
        if component_tag is None:
            short_name = component_name.split('.')[-1] if '.' in component_name else component_name
            component_tag = application.find(f'.//{component_type}[@{{http://schemas.android.com/apk/res/android}}name=".{short_name}"]')
        
        if component_tag is not None:
            exported = component_tag.get('{http://schemas.android.com/apk/res/android}exported')
            if exported is not None:
                return exported.lower() == 'true'
            
            intent_filter = component_tag.find('.//intent-filter')
            if intent_filter is not None:
                return True
        
        return False
    
    def _get_intent_filters(self, apk: APK, component_name: str, component_type: str) -> List[str]:
        intent_filters = []
        manifest = apk.get_android_manifest_xml()
        application = manifest.find('.//application')
        
        if application is None:
            return intent_filters
        
        component_tag = application.find(f'.//{component_type}[@{{http://schemas.android.com/apk/res/android}}name="{component_name}"]')
        
        if component_tag is None:
            short_name = component_name.split('.')[-1] if '.' in component_name else component_name
            component_tag = application.find(f'.//{component_type}[@{{http://schemas.android.com/apk/res/android}}name=".{short_name}"]')
        
        if component_tag is not None:
            for intent_filter in component_tag.findall('.//intent-filter'):
                for action in intent_filter.findall('.//action'):
                    action_name = action.get('{http://schemas.android.com/apk/res/android}name')
                    if action_name:
                        intent_filters.append(action_name)
        
        return intent_filters
    
    def _extract_security_flags(self, apk: APK) -> SecurityFlags:
        manifest = apk.get_android_manifest_xml()
        application = manifest.find('.//application')
        
        flags = SecurityFlags()
        
        if application is not None:
            debuggable = application.get('{http://schemas.android.com/apk/res/android}debuggable')
            flags.debuggable = debuggable is not None and debuggable.lower() == 'true'
            
            allow_backup = application.get('{http://schemas.android.com/apk/res/android}allowBackup')
            flags.allow_backup = allow_backup is None or allow_backup.lower() == 'true'
            
            uses_cleartext = application.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')
            flags.uses_cleartext_traffic = uses_cleartext is None or uses_cleartext.lower() == 'true'
            
            test_only = application.get('{http://schemas.android.com/apk/res/android}testOnly')
            flags.test_only = test_only is not None and test_only.lower() == 'true'
        
        return flags
    
    def _filter_dangerous_permissions(self, permissions: List[str]) -> List[str]:
        dangerous = [
            'READ_CALENDAR', 'WRITE_CALENDAR',
            'CAMERA',
            'READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
            'RECORD_AUDIO',
            'READ_PHONE_STATE', 'READ_PHONE_NUMBERS', 'CALL_PHONE',
            'READ_CALL_LOG', 'WRITE_CALL_LOG', 'ADD_VOICEMAIL',
            'USE_SIP', 'PROCESS_OUTGOING_CALLS', 'ANSWER_PHONE_CALLS',
            'BODY_SENSORS',
            'SEND_SMS', 'RECEIVE_SMS', 'READ_SMS',
            'RECEIVE_WAP_PUSH', 'RECEIVE_MMS',
            'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
            'ACCESS_MEDIA_LOCATION'
        ]
        
        dangerous_perms = []
        for perm in permissions:
            perm_name = perm.split('.')[-1] if '.' in perm else perm
            if any(d in perm_name for d in dangerous):
                dangerous_perms.append(perm)
        
        return dangerous_perms
    
    def _extract_native_libraries(self, apk: APK) -> List[str]:
        libraries = []
        try:
            for file in apk.get_files():
                if file.startswith('lib/') and file.endswith('.so'):
                    libraries.append(file)
        except:
            pass
        
        return libraries
    
    def _extract_certificate_info(self, apk: APK) -> Optional[Dict]:
        try:
            cert = apk.get_certificate_der(apk.get_signature_names()[0])
            if cert:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                
                return {
                    'issuer': cert_obj.issuer.rfc4514_string(),
                    'subject': cert_obj.subject.rfc4514_string(),
                    'serial_number': str(cert_obj.serial_number),
                    'not_valid_before': cert_obj.not_valid_before_utc.isoformat(),
                    'not_valid_after': cert_obj.not_valid_after_utc.isoformat()
                }
        except:
            pass
        
        return None

# -*- coding: utf-8 -*-
"""
Sources and Sinks Database
==========================

Implementa el Repository Pattern para gestionar la base de datos de
APIs sensibles de Android (sources y sinks).

Sources: APIs que producen datos sensibles (ej: getDeviceId, getLocation)
Sinks: APIs que consumen/envían datos (ej: sendSMS, HttpURLConnection)

Patrones utilizados:
    - Repository Pattern: Abstrae el acceso a datos
    - Singleton Pattern: Una única instancia de la base de datos
    - Factory Pattern: Creación de objetos SourceSink

Autor: Framework de Detección de Vulnerabilidades Android
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from abc import ABC, abstractmethod


class SourceSinkCategory(Enum):
    """
    Categorías de vulnerabilidades según OWASP Mobile Top 10.
    
    Cada categoría representa un tipo de vulnerabilidad que puede
    ser detectada mediante taint analysis.
    """
    # Fugas de información sensible
    DEVICE_ID_LEAK = auto()       # Fuga de identificadores del dispositivo
    LOCATION_LEAK = auto()        # Fuga de ubicación
    CONTACT_LEAK = auto()         # Fuga de contactos
    SMS_LEAK = auto()             # Fuga de mensajes SMS
    CALL_LOG_LEAK = auto()        # Fuga de registro de llamadas
    CALENDAR_LEAK = auto()        # Fuga de calendario
    CAMERA_LEAK = auto()          # Fuga de cámara/micrófono
    
    # Comunicación insegura
    NETWORK_LEAK = auto()         # Envío de datos por red
    LOG_LEAK = auto()             # Fuga a logs del sistema
    FILE_LEAK = auto()            # Fuga a archivos
    
    # Escalación de privilegios
    PRIVILEGE_ESCALATION = auto() # Intento de escalación
    CODE_INJECTION = auto()       # Inyección de código
    
    # Criptografía débil
    WEAK_CRYPTO = auto()          # Uso de criptografía débil
    
    # Almacenamiento inseguro
    INSECURE_STORAGE = auto()     # Almacenamiento inseguro de datos
    
    # Otros
    INTER_APP_COMMUNICATION = auto()  # Comunicación entre apps
    REFLECTION = auto()               # Uso de reflection


class SourceSinkType(Enum):
    """Tipo de API: Source o Sink."""
    SOURCE = "source"
    SINK = "sink"


@dataclass(frozen=True)
class SourceSink:
    """
    Representa una API source o sink.
    
    Attributes:
        class_name: Nombre completo de la clase (ej: android.telephony.TelephonyManager)
        method_name: Nombre del método (ej: getDeviceId)
        signature: Firma completa del método
        api_type: Si es SOURCE o SINK
        category: Categoría de vulnerabilidad asociada
        description: Descripción legible del propósito
        risk_level: Nivel de riesgo (1-10)
        required_permissions: Permisos Android necesarios
    """
    class_name: str
    method_name: str
    signature: str
    api_type: SourceSinkType
    category: SourceSinkCategory
    description: str
    risk_level: int = 5
    required_permissions: tuple = field(default_factory=tuple)
    
    @property
    def full_name(self) -> str:
        """Retorna el nombre completo: Clase.método."""
        return f"{self.class_name}.{self.method_name}"
    
    @property
    def short_class_name(self) -> str:
        """Retorna solo el nombre de la clase sin paquete."""
        return self.class_name.split('.')[-1]


class ISourceSinkRepository(ABC):
    """
    Interface para el repositorio de sources y sinks.
    Implementa el Repository Pattern.
    """
    
    @abstractmethod
    def get_all_sources(self) -> List[SourceSink]:
        """Obtiene todas las APIs source."""
        pass
    
    @abstractmethod
    def get_all_sinks(self) -> List[SourceSink]:
        """Obtiene todas las APIs sink."""
        pass
    
    @abstractmethod
    def get_by_category(self, category: SourceSinkCategory) -> List[SourceSink]:
        """Obtiene APIs por categoría de vulnerabilidad."""
        pass
    
    @abstractmethod
    def is_source(self, class_name: str, method_name: str) -> bool:
        """Verifica si una API es un source."""
        pass
    
    @abstractmethod
    def is_sink(self, class_name: str, method_name: str) -> bool:
        """Verifica si una API es un sink."""
        pass


class SourcesSinksDatabase(ISourceSinkRepository):
    """
    Base de datos de Sources y Sinks para Android.
    
    Implementa Singleton Pattern para asegurar una única instancia.
    Contiene las APIs sensibles de Android categorizadas.
    
    Usage:
        >>> db = SourcesSinksDatabase()
        >>> sources = db.get_all_sources()
        >>> is_source = db.is_source("TelephonyManager", "getDeviceId")
    """
    
    _instance: Optional['SourcesSinksDatabase'] = None
    
    def __new__(cls) -> 'SourcesSinksDatabase':
        """Singleton Pattern: Retorna siempre la misma instancia."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Inicializa la base de datos con todas las APIs conocidas."""
        if self._initialized:
            return
        
        self._sources: List[SourceSink] = []
        self._sinks: List[SourceSink] = []
        self._source_lookup: Dict[str, SourceSink] = {}
        self._sink_lookup: Dict[str, SourceSink] = {}
        
        self._initialize_sources()
        self._initialize_sinks()
        self._build_lookup_tables()
        
        self._initialized = True
    
    def _initialize_sources(self) -> None:
        """Inicializa todas las APIs source conocidas."""
        
        # ==================== DEVICE ID SOURCES ====================
        self._sources.extend([
            SourceSink(
                class_name="android.telephony.TelephonyManager",
                method_name="getDeviceId",
                signature="()Ljava/lang/String;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.DEVICE_ID_LEAK,
                description="Obtiene el IMEI/MEID del dispositivo",
                risk_level=9,
                required_permissions=("READ_PHONE_STATE",)
            ),
            SourceSink(
                class_name="android.telephony.TelephonyManager",
                method_name="getImei",
                signature="()Ljava/lang/String;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.DEVICE_ID_LEAK,
                description="Obtiene el IMEI del dispositivo",
                risk_level=9,
                required_permissions=("READ_PHONE_STATE",)
            ),
            SourceSink(
                class_name="android.telephony.TelephonyManager",
                method_name="getSubscriberId",
                signature="()Ljava/lang/String;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.DEVICE_ID_LEAK,
                description="Obtiene el IMSI del suscriptor",
                risk_level=9,
                required_permissions=("READ_PHONE_STATE",)
            ),
            SourceSink(
                class_name="android.telephony.TelephonyManager",
                method_name="getLine1Number",
                signature="()Ljava/lang/String;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.DEVICE_ID_LEAK,
                description="Obtiene el número de teléfono",
                risk_level=9,
                required_permissions=("READ_PHONE_STATE",)
            ),
            SourceSink(
                class_name="android.telephony.TelephonyManager",
                method_name="getSimSerialNumber",
                signature="()Ljava/lang/String;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.DEVICE_ID_LEAK,
                description="Obtiene el número de serie de la SIM",
                risk_level=8,
                required_permissions=("READ_PHONE_STATE",)
            ),
            SourceSink(
                class_name="android.provider.Settings$Secure",
                method_name="getString",
                signature="(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.DEVICE_ID_LEAK,
                description="Puede obtener ANDROID_ID",
                risk_level=7,
                required_permissions=()
            ),
            SourceSink(
                class_name="android.os.Build",
                method_name="getSerial",
                signature="()Ljava/lang/String;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.DEVICE_ID_LEAK,
                description="Obtiene el número de serie del hardware",
                risk_level=8,
                required_permissions=("READ_PHONE_STATE",)
            ),
        ])
        
        # ==================== LOCATION SOURCES ====================
        self._sources.extend([
            SourceSink(
                class_name="android.location.LocationManager",
                method_name="getLastKnownLocation",
                signature="(Ljava/lang/String;)Landroid/location/Location;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.LOCATION_LEAK,
                description="Obtiene la última ubicación conocida",
                risk_level=8,
                required_permissions=("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION")
            ),
            SourceSink(
                class_name="android.location.Location",
                method_name="getLatitude",
                signature="()D",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.LOCATION_LEAK,
                description="Obtiene la latitud de una ubicación",
                risk_level=8,
                required_permissions=()
            ),
            SourceSink(
                class_name="android.location.Location",
                method_name="getLongitude",
                signature="()D",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.LOCATION_LEAK,
                description="Obtiene la longitud de una ubicación",
                risk_level=8,
                required_permissions=()
            ),
            SourceSink(
                class_name="com.google.android.gms.location.FusedLocationProviderClient",
                method_name="getLastLocation",
                signature="()Lcom/google/android/gms/tasks/Task;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.LOCATION_LEAK,
                description="Obtiene ubicación via Google Play Services",
                risk_level=8,
                required_permissions=("ACCESS_FINE_LOCATION",)
            ),
        ])
        
        # ==================== CONTACT SOURCES ====================
        self._sources.extend([
            SourceSink(
                class_name="android.content.ContentResolver",
                method_name="query",
                signature="(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.CONTACT_LEAK,
                description="Consulta datos del ContentProvider (contactos, SMS, etc.)",
                risk_level=7,
                required_permissions=("READ_CONTACTS", "READ_SMS", "READ_CALL_LOG")
            ),
            SourceSink(
                class_name="android.database.Cursor",
                method_name="getString",
                signature="(I)Ljava/lang/String;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.CONTACT_LEAK,
                description="Obtiene string de un cursor de base de datos",
                risk_level=6,
                required_permissions=()
            ),
        ])
        
        # ==================== SMS SOURCES ====================
        self._sources.extend([
            SourceSink(
                class_name="android.telephony.SmsMessage",
                method_name="getMessageBody",
                signature="()Ljava/lang/String;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.SMS_LEAK,
                description="Obtiene el contenido de un SMS",
                risk_level=9,
                required_permissions=("READ_SMS",)
            ),
            SourceSink(
                class_name="android.telephony.SmsMessage",
                method_name="getOriginatingAddress",
                signature="()Ljava/lang/String;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.SMS_LEAK,
                description="Obtiene el remitente de un SMS",
                risk_level=7,
                required_permissions=("READ_SMS",)
            ),
        ])
        
        # ==================== CAMERA/MICROPHONE SOURCES ====================
        self._sources.extend([
            SourceSink(
                class_name="android.media.MediaRecorder",
                method_name="setAudioSource",
                signature="(I)V",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.CAMERA_LEAK,
                description="Configura fuente de audio para grabación",
                risk_level=9,
                required_permissions=("RECORD_AUDIO",)
            ),
            SourceSink(
                class_name="android.hardware.Camera",
                method_name="takePicture",
                signature="(Landroid/hardware/Camera$ShutterCallback;Landroid/hardware/Camera$PictureCallback;Landroid/hardware/Camera$PictureCallback;)V",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.CAMERA_LEAK,
                description="Captura una foto",
                risk_level=8,
                required_permissions=("CAMERA",)
            ),
        ])
        
        # ==================== ACCOUNT SOURCES ====================
        self._sources.extend([
            SourceSink(
                class_name="android.accounts.AccountManager",
                method_name="getAccounts",
                signature="()[Landroid/accounts/Account;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.CONTACT_LEAK,
                description="Obtiene cuentas del dispositivo",
                risk_level=7,
                required_permissions=("GET_ACCOUNTS",)
            ),
            SourceSink(
                class_name="android.accounts.AccountManager",
                method_name="getAccountsByType",
                signature="(Ljava/lang/String;)[Landroid/accounts/Account;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.CONTACT_LEAK,
                description="Obtiene cuentas por tipo",
                risk_level=7,
                required_permissions=("GET_ACCOUNTS",)
            ),
        ])
        
        # ==================== CLIPBOARD SOURCES ====================
        self._sources.extend([
            SourceSink(
                class_name="android.content.ClipboardManager",
                method_name="getPrimaryClip",
                signature="()Landroid/content/ClipData;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.INSECURE_STORAGE,
                description="Obtiene contenido del portapapeles",
                risk_level=6,
                required_permissions=()
            ),
        ])
        
        # ==================== INTENT DATA SOURCES ====================
        self._sources.extend([
            SourceSink(
                class_name="android.content.Intent",
                method_name="getStringExtra",
                signature="(Ljava/lang/String;)Ljava/lang/String;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.INTER_APP_COMMUNICATION,
                description="Obtiene datos extras de un Intent",
                risk_level=5,
                required_permissions=()
            ),
            SourceSink(
                class_name="android.content.Intent",
                method_name="getData",
                signature="()Landroid/net/Uri;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.INTER_APP_COMMUNICATION,
                description="Obtiene URI de datos del Intent",
                risk_level=5,
                required_permissions=()
            ),
        ])
        
        # ==================== SHARED PREFERENCES SOURCES ====================
        self._sources.extend([
            SourceSink(
                class_name="android.content.SharedPreferences",
                method_name="getString",
                signature="(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                api_type=SourceSinkType.SOURCE,
                category=SourceSinkCategory.INSECURE_STORAGE,
                description="Lee string de SharedPreferences",
                risk_level=5,
                required_permissions=()
            ),
        ])
    
    def _initialize_sinks(self) -> None:
        """Inicializa todas las APIs sink conocidas."""
        
        # ==================== NETWORK SINKS ====================
        self._sinks.extend([
            SourceSink(
                class_name="java.net.HttpURLConnection",
                method_name="getOutputStream",
                signature="()Ljava/io/OutputStream;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.NETWORK_LEAK,
                description="Envía datos por HTTP",
                risk_level=8,
                required_permissions=("INTERNET",)
            ),
            SourceSink(
                class_name="java.net.URL",
                method_name="openConnection",
                signature="()Ljava/net/URLConnection;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.NETWORK_LEAK,
                description="Abre conexión de red",
                risk_level=7,
                required_permissions=("INTERNET",)
            ),
            SourceSink(
                class_name="org.apache.http.client.HttpClient",
                method_name="execute",
                signature="(Lorg/apache/http/client/methods/HttpUriRequest;)Lorg/apache/http/HttpResponse;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.NETWORK_LEAK,
                description="Ejecuta petición HTTP (Apache)",
                risk_level=8,
                required_permissions=("INTERNET",)
            ),
            SourceSink(
                class_name="okhttp3.OkHttpClient",
                method_name="newCall",
                signature="(Lokhttp3/Request;)Lokhttp3/Call;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.NETWORK_LEAK,
                description="Crea llamada HTTP (OkHttp)",
                risk_level=8,
                required_permissions=("INTERNET",)
            ),
            SourceSink(
                class_name="java.net.Socket",
                method_name="getOutputStream",
                signature="()Ljava/io/OutputStream;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.NETWORK_LEAK,
                description="Envía datos por socket",
                risk_level=8,
                required_permissions=("INTERNET",)
            ),
            SourceSink(
                class_name="android.webkit.WebView",
                method_name="loadUrl",
                signature="(Ljava/lang/String;)V",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.NETWORK_LEAK,
                description="Carga URL en WebView",
                risk_level=6,
                required_permissions=("INTERNET",)
            ),
        ])
        
        # ==================== SMS SINKS ====================
        self._sinks.extend([
            SourceSink(
                class_name="android.telephony.SmsManager",
                method_name="sendTextMessage",
                signature="(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.SMS_LEAK,
                description="Envía SMS de texto",
                risk_level=9,
                required_permissions=("SEND_SMS",)
            ),
            SourceSink(
                class_name="android.telephony.SmsManager",
                method_name="sendDataMessage",
                signature="(Ljava/lang/String;Ljava/lang/String;S[BLandroid/app/PendingIntent;Landroid/app/PendingIntent;)V",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.SMS_LEAK,
                description="Envía SMS de datos",
                risk_level=9,
                required_permissions=("SEND_SMS",)
            ),
            SourceSink(
                class_name="android.telephony.SmsManager",
                method_name="sendMultipartTextMessage",
                signature="(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;)V",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.SMS_LEAK,
                description="Envía SMS multiparte",
                risk_level=9,
                required_permissions=("SEND_SMS",)
            ),
        ])
        
        # ==================== LOG SINKS ====================
        self._sinks.extend([
            SourceSink(
                class_name="android.util.Log",
                method_name="d",
                signature="(Ljava/lang/String;Ljava/lang/String;)I",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.LOG_LEAK,
                description="Escribe en log de debug",
                risk_level=5,
                required_permissions=()
            ),
            SourceSink(
                class_name="android.util.Log",
                method_name="i",
                signature="(Ljava/lang/String;Ljava/lang/String;)I",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.LOG_LEAK,
                description="Escribe en log de info",
                risk_level=5,
                required_permissions=()
            ),
            SourceSink(
                class_name="android.util.Log",
                method_name="e",
                signature="(Ljava/lang/String;Ljava/lang/String;)I",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.LOG_LEAK,
                description="Escribe en log de error",
                risk_level=5,
                required_permissions=()
            ),
            SourceSink(
                class_name="android.util.Log",
                method_name="v",
                signature="(Ljava/lang/String;Ljava/lang/String;)I",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.LOG_LEAK,
                description="Escribe en log verbose",
                risk_level=4,
                required_permissions=()
            ),
            SourceSink(
                class_name="android.util.Log",
                method_name="w",
                signature="(Ljava/lang/String;Ljava/lang/String;)I",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.LOG_LEAK,
                description="Escribe en log de warning",
                risk_level=5,
                required_permissions=()
            ),
            SourceSink(
                class_name="java.io.PrintStream",
                method_name="println",
                signature="(Ljava/lang/String;)V",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.LOG_LEAK,
                description="Imprime en System.out",
                risk_level=4,
                required_permissions=()
            ),
        ])
        
        # ==================== FILE SINKS ====================
        self._sinks.extend([
            SourceSink(
                class_name="java.io.FileOutputStream",
                method_name="write",
                signature="([B)V",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.FILE_LEAK,
                description="Escribe bytes en archivo",
                risk_level=6,
                required_permissions=("WRITE_EXTERNAL_STORAGE",)
            ),
            SourceSink(
                class_name="java.io.FileWriter",
                method_name="write",
                signature="(Ljava/lang/String;)V",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.FILE_LEAK,
                description="Escribe string en archivo",
                risk_level=6,
                required_permissions=("WRITE_EXTERNAL_STORAGE",)
            ),
            SourceSink(
                class_name="android.content.SharedPreferences$Editor",
                method_name="putString",
                signature="(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.INSECURE_STORAGE,
                description="Guarda string en SharedPreferences",
                risk_level=5,
                required_permissions=()
            ),
        ])
        
        # ==================== INTENT SINKS ====================
        self._sinks.extend([
            SourceSink(
                class_name="android.content.Context",
                method_name="startActivity",
                signature="(Landroid/content/Intent;)V",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.INTER_APP_COMMUNICATION,
                description="Inicia una actividad",
                risk_level=5,
                required_permissions=()
            ),
            SourceSink(
                class_name="android.content.Context",
                method_name="sendBroadcast",
                signature="(Landroid/content/Intent;)V",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.INTER_APP_COMMUNICATION,
                description="Envía broadcast",
                risk_level=6,
                required_permissions=()
            ),
            SourceSink(
                class_name="android.content.Context",
                method_name="startService",
                signature="(Landroid/content/Intent;)Landroid/content/ComponentName;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.INTER_APP_COMMUNICATION,
                description="Inicia un servicio",
                risk_level=5,
                required_permissions=()
            ),
        ])
        
        # ==================== REFLECTION SINKS ====================
        self._sinks.extend([
            SourceSink(
                class_name="java.lang.reflect.Method",
                method_name="invoke",
                signature="(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.REFLECTION,
                description="Invoca método por reflection",
                risk_level=7,
                required_permissions=()
            ),
            SourceSink(
                class_name="java.lang.Class",
                method_name="forName",
                signature="(Ljava/lang/String;)Ljava/lang/Class;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.REFLECTION,
                description="Carga clase dinámicamente",
                risk_level=6,
                required_permissions=()
            ),
            SourceSink(
                class_name="dalvik.system.DexClassLoader",
                method_name="loadClass",
                signature="(Ljava/lang/String;)Ljava/lang/Class;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.CODE_INJECTION,
                description="Carga clase desde DEX externo",
                risk_level=9,
                required_permissions=()
            ),
        ])
        
        # ==================== CRYPTO SINKS (débiles) ====================
        self._sinks.extend([
            SourceSink(
                class_name="javax.crypto.Cipher",
                method_name="getInstance",
                signature="(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.WEAK_CRYPTO,
                description="Obtiene instancia de cifrado (verificar algoritmo)",
                risk_level=5,
                required_permissions=()
            ),
            SourceSink(
                class_name="java.security.MessageDigest",
                method_name="getInstance",
                signature="(Ljava/lang/String;)Ljava/security/MessageDigest;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.WEAK_CRYPTO,
                description="Obtiene instancia de hash (verificar algoritmo)",
                risk_level=4,
                required_permissions=()
            ),
        ])
        
        # ==================== CONTENT PROVIDER SINKS ====================
        self._sinks.extend([
            SourceSink(
                class_name="android.content.ContentResolver",
                method_name="insert",
                signature="(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.INSECURE_STORAGE,
                description="Inserta datos en ContentProvider",
                risk_level=5,
                required_permissions=()
            ),
            SourceSink(
                class_name="android.content.ContentResolver",
                method_name="update",
                signature="(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I",
                api_type=SourceSinkType.SINK,
                category=SourceSinkCategory.INSECURE_STORAGE,
                description="Actualiza datos en ContentProvider",
                risk_level=5,
                required_permissions=()
            ),
        ])
    
    def _build_lookup_tables(self) -> None:
        """Construye tablas de búsqueda rápida para sources y sinks."""
        for source in self._sources:
            key = self._make_lookup_key(source.class_name, source.method_name)
            self._source_lookup[key] = source
            
            # También agregar con nombre corto de clase
            short_key = self._make_lookup_key(source.short_class_name, source.method_name)
            if short_key not in self._source_lookup:
                self._source_lookup[short_key] = source
        
        for sink in self._sinks:
            key = self._make_lookup_key(sink.class_name, sink.method_name)
            self._sink_lookup[key] = sink
            
            # También agregar con nombre corto de clase
            short_key = self._make_lookup_key(sink.short_class_name, sink.method_name)
            if short_key not in self._sink_lookup:
                self._sink_lookup[short_key] = sink
    
    @staticmethod
    def _make_lookup_key(class_name: str, method_name: str) -> str:
        """Crea una clave de búsqueda normalizada."""
        # Normalizar: remover 'L' inicial y ';' final si existen (formato Dalvik)
        clean_class = class_name.replace('/', '.').strip('L').rstrip(';')
        return f"{clean_class}.{method_name}".lower()
    
    # ==================== INTERFACE IMPLEMENTATION ====================
    
    def get_all_sources(self) -> List[SourceSink]:
        """Retorna todas las APIs source."""
        return self._sources.copy()
    
    def get_all_sinks(self) -> List[SourceSink]:
        """Retorna todas las APIs sink."""
        return self._sinks.copy()
    
    def get_by_category(self, category: SourceSinkCategory) -> List[SourceSink]:
        """Retorna todas las APIs de una categoría específica."""
        result = []
        result.extend([s for s in self._sources if s.category == category])
        result.extend([s for s in self._sinks if s.category == category])
        return result
    
    def is_source(self, class_name: str, method_name: str) -> bool:
        """Verifica si una combinación clase.método es un source."""
        key = self._make_lookup_key(class_name, method_name)
        return key in self._source_lookup
    
    def is_sink(self, class_name: str, method_name: str) -> bool:
        """Verifica si una combinación clase.método es un sink."""
        key = self._make_lookup_key(class_name, method_name)
        return key in self._sink_lookup
    
    def get_source(self, class_name: str, method_name: str) -> Optional[SourceSink]:
        """Obtiene información de un source específico."""
        key = self._make_lookup_key(class_name, method_name)
        return self._source_lookup.get(key)
    
    def get_sink(self, class_name: str, method_name: str) -> Optional[SourceSink]:
        """Obtiene información de un sink específico."""
        key = self._make_lookup_key(class_name, method_name)
        return self._sink_lookup.get(key)
    
    def get_source_methods(self) -> Set[str]:
        """Retorna conjunto de nombres de métodos source para búsqueda rápida."""
        return {s.method_name for s in self._sources}
    
    def get_sink_methods(self) -> Set[str]:
        """Retorna conjunto de nombres de métodos sink para búsqueda rápida."""
        return {s.method_name for s in self._sinks}
    
    # ==================== STATISTICS ====================
    
    def get_statistics(self) -> Dict[str, int]:
        """Retorna estadísticas de la base de datos."""
        stats = {
            "total_sources": len(self._sources),
            "total_sinks": len(self._sinks),
            "total_apis": len(self._sources) + len(self._sinks),
            "categories": {}
        }
        
        for category in SourceSinkCategory:
            count = len(self.get_by_category(category))
            if count > 0:
                stats["categories"][category.name] = count
        
        return stats
    
    def __repr__(self) -> str:
        """Representación string de la base de datos."""
        stats = self.get_statistics()
        return (
            f"SourcesSinksDatabase("
            f"sources={stats['total_sources']}, "
            f"sinks={stats['total_sinks']}, "
            f"categories={len(stats['categories'])})"
        )

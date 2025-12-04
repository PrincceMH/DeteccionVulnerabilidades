"""
Módulo 3: Transformer - Code Tokenizer
========================================

Este módulo se encarga de tokenizar código Android (Java/Smali) 
para su procesamiento por modelos de lenguaje como CodeBERT.

El tokenizador convierte:
- Nombres de clases Android
- Firmas de métodos
- Flujos de datos (source → sink)
- Contexto del código

En una representación numérica que el modelo puede procesar.

"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from enum import Enum, auto
import re
from abc import ABC, abstractmethod


class TokenType(Enum):
    """
    Tipos de tokens que podemos encontrar en código Android.
    
    Cada tipo de token tiene un significado semántico diferente
    que el modelo debe aprender a distinguir.
    """
    # Tokens de estructura
    CLASS_NAME = auto()      # android.telephony.TelephonyManager
    METHOD_NAME = auto()     # getDeviceId, sendTextMessage
    PACKAGE_NAME = auto()    # com.example.app
    
    # Tokens de flujo de datos
    SOURCE_API = auto()      # API que genera datos sensibles
    SINK_API = auto()        # API que consume/expone datos
    FLOW_ARROW = auto()      # Indicador de flujo (→)
    
    # Tokens de seguridad
    PERMISSION = auto()      # android.permission.READ_PHONE_STATE
    CATEGORY = auto()        # DEVICE_ID_LEAK, SMS_LEAK
    RISK_LEVEL = auto()      # HIGH, MEDIUM, LOW
    
    # Tokens especiales
    SPECIAL = auto()         # [CLS], [SEP], [PAD], etc.
    UNKNOWN = auto()         # Token desconocido


@dataclass
class Token:
    """
    Representa un token individual con su metadata.
    
    Attributes:
        text: Texto original del token
        token_type: Tipo semántico del token
        token_id: ID numérico para el modelo
        position: Posición en la secuencia
        metadata: Información adicional
    """
    text: str
    token_type: TokenType
    token_id: int = 0
    position: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self) -> str:
        return f"Token({self.text}, {self.token_type.name})"


@dataclass
class TokenizedSequence:
    """
    Secuencia de tokens lista para el modelo.
    
    Contiene todos los IDs y máscaras necesarias para
    la entrada del Transformer.
    """
    # IDs de tokens
    input_ids: List[int] = field(default_factory=list)
    
    # Máscara de atención (1 = token real, 0 = padding)
    attention_mask: List[int] = field(default_factory=list)
    
    # IDs de tipo de token (para distinguir source vs sink)
    token_type_ids: List[int] = field(default_factory=list)
    
    # Tokens originales para debugging
    tokens: List[Token] = field(default_factory=list)
    
    # Longitud real (sin padding)
    real_length: int = 0
    
    @property
    def is_valid(self) -> bool:
        """Verifica que la secuencia sea válida."""
        return (
            len(self.input_ids) == len(self.attention_mask) == len(self.token_type_ids)
            and len(self.input_ids) > 0
        )
    
    def to_dict(self) -> Dict[str, List[int]]:
        """Convierte a diccionario para el modelo."""
        return {
            "input_ids": self.input_ids,
            "attention_mask": self.attention_mask,
            "token_type_ids": self.token_type_ids
        }


class VocabularyBuilder:
    """
    Construye y gestiona el vocabulario para el tokenizador.
    
    El vocabulario mapea tokens de texto a IDs numéricos
    que el modelo puede procesar.
    
    Tokens especiales:
        [PAD] = 0   - Padding para igualar longitudes
        [UNK] = 1   - Token desconocido
        [CLS] = 2   - Inicio de secuencia
        [SEP] = 3   - Separador entre source y sink
        [MASK] = 4  - Para entrenamiento MLM
        [FLOW] = 5  - Indicador de flujo →
    """
    
    # Tokens especiales predefinidos
    SPECIAL_TOKENS = {
        "[PAD]": 0,
        "[UNK]": 1,
        "[CLS]": 2,
        "[SEP]": 3,
        "[MASK]": 4,
        "[FLOW]": 5,
        "[HIGH_RISK]": 6,
        "[MED_RISK]": 7,
        "[LOW_RISK]": 8,
    }
    
    def __init__(self):
        """Inicializa el vocabulario con tokens especiales."""
        # Vocabulario: texto → id
        self.token_to_id: Dict[str, int] = dict(self.SPECIAL_TOKENS)
        
        # Vocabulario inverso: id → texto
        self.id_to_token: Dict[int, str] = {
            v: k for k, v in self.SPECIAL_TOKENS.items()
        }
        
        # Siguiente ID disponible
        self._next_id = len(self.SPECIAL_TOKENS)
        
        # Frecuencia de tokens (para análisis)
        self.token_frequency: Dict[str, int] = {}
    
    @property
    def vocab_size(self) -> int:
        """Tamaño actual del vocabulario."""
        return len(self.token_to_id)
    
    @property
    def pad_token_id(self) -> int:
        return self.SPECIAL_TOKENS["[PAD]"]
    
    @property
    def unk_token_id(self) -> int:
        return self.SPECIAL_TOKENS["[UNK]"]
    
    @property
    def cls_token_id(self) -> int:
        return self.SPECIAL_TOKENS["[CLS]"]
    
    @property
    def sep_token_id(self) -> int:
        return self.SPECIAL_TOKENS["[SEP]"]
    
    def add_token(self, token: str) -> int:
        """
        Añade un token al vocabulario si no existe.
        
        Args:
            token: Texto del token a añadir
            
        Returns:
            ID del token (nuevo o existente)
        """
        if token not in self.token_to_id:
            self.token_to_id[token] = self._next_id
            self.id_to_token[self._next_id] = token
            self._next_id += 1
        
        # Actualizar frecuencia
        self.token_frequency[token] = self.token_frequency.get(token, 0) + 1
        
        return self.token_to_id[token]
    
    def get_id(self, token: str) -> int:
        """
        Obtiene el ID de un token.
        
        Args:
            token: Texto del token
            
        Returns:
            ID del token o ID de [UNK] si no existe
        """
        return self.token_to_id.get(token, self.unk_token_id)
    
    def get_token(self, token_id: int) -> str:
        """
        Obtiene el texto de un ID.
        
        Args:
            token_id: ID numérico
            
        Returns:
            Texto del token o [UNK] si no existe
        """
        return self.id_to_token.get(token_id, "[UNK]")
    
    def batch_add_tokens(self, tokens: List[str]) -> List[int]:
        """Añade múltiples tokens y retorna sus IDs."""
        return [self.add_token(t) for t in tokens]


class AndroidCodeTokenizer:
    """
    Tokenizador especializado para código Android.
    
    Este tokenizador entiende la estructura del código Android
    y puede tokenizar:
    
    1. Nombres de clases Android (camelCase, paquetes)
    2. Firmas de métodos
    3. Flujos source → sink
    4. Permisos y categorías
    
    Ejemplo de uso:
        tokenizer = AndroidCodeTokenizer()
        
        # Tokenizar un flujo
        sequence = tokenizer.tokenize_flow(
            source="android.telephony.TelephonyManager.getDeviceId",
            sink="android.telephony.SmsManager.sendTextMessage"
        )
        
        # Usar con el modelo
        model_input = sequence.to_dict()
    """
    
    def __init__(
        self,
        max_length: int = 256,
        vocabulary: Optional[VocabularyBuilder] = None
    ):
        """
        Inicializa el tokenizador.
        
        Args:
            max_length: Longitud máxima de secuencia
            vocabulary: Vocabulario existente o None para crear nuevo
        """
        self.max_length = max_length
        self.vocab = vocabulary or VocabularyBuilder()
        
        # Patrones para parsear código Android
        self._class_pattern = re.compile(
            r'L?([a-zA-Z_][a-zA-Z0-9_]*(?:/[a-zA-Z_][a-zA-Z0-9_]*)*);?'
        )
        self._method_pattern = re.compile(
            r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        )
        
        # Pre-cargar tokens comunes de Android
        self._preload_android_tokens()
    
    def _preload_android_tokens(self):
        """Pre-carga tokens comunes de Android en el vocabulario."""
        # Clases comunes
        common_classes = [
            "TelephonyManager", "SmsManager", "LocationManager",
            "ContentResolver", "SharedPreferences", "Log",
            "HttpURLConnection", "WebView", "Intent", "Activity",
            "Context", "Bundle", "Uri", "Cursor", "Database"
        ]
        
        # Métodos comunes (sources y sinks)
        common_methods = [
            "getDeviceId", "getLine1Number", "getSimSerialNumber",
            "sendTextMessage", "getLastKnownLocation", "query",
            "openConnection", "write", "println", "loadUrl",
            "putString", "getString", "getInputStream", "getOutputStream"
        ]
        
        # Permisos comunes
        common_permissions = [
            "READ_PHONE_STATE", "SEND_SMS", "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION", "INTERNET", "READ_CONTACTS",
            "WRITE_EXTERNAL_STORAGE", "CAMERA", "RECORD_AUDIO"
        ]
        
        # Añadir al vocabulario
        for token in common_classes + common_methods + common_permissions:
            self.vocab.add_token(token)
    
    def _split_camel_case(self, text: str) -> List[str]:
        """
        Divide camelCase en tokens separados.
        
        Ejemplo:
            "getDeviceId" → ["get", "Device", "Id"]
            "TelephonyManager" → ["Telephony", "Manager"]
        """
        # Insertar espacio antes de mayúsculas
        tokens = re.sub(r'([A-Z])', r' \1', text).split()
        return [t.strip() for t in tokens if t.strip()]
    
    def _split_package_name(self, package: str) -> List[str]:
        """
        Divide nombre de paquete en componentes.
        
        Ejemplo:
            "android.telephony.TelephonyManager" 
            → ["android", "telephony", "TelephonyManager"]
        """
        # Limpiar formato Smali si existe
        package = package.replace('/', '.').strip('L;')
        return package.split('.')
    
    def _tokenize_api_name(self, api: str) -> List[Token]:
        """
        Tokeniza un nombre de API Android.
        
        Ejemplo:
            "android.telephony.TelephonyManager.getDeviceId"
            → [Token(android), Token(telephony), Token(Telephony), 
               Token(Manager), Token(get), Token(Device), Token(Id)]
        """
        tokens = []
        
        # Separar clase y método
        parts = api.rsplit('.', 1)
        
        if len(parts) == 2:
            class_path, method_name = parts
            
            # Tokenizar path de la clase
            for component in self._split_package_name(class_path):
                # Dividir camelCase en el último componente (nombre de clase)
                if '.' not in class_path or component == self._split_package_name(class_path)[-1]:
                    for sub_token in self._split_camel_case(component):
                        token_id = self.vocab.add_token(sub_token)
                        tokens.append(Token(
                            text=sub_token,
                            token_type=TokenType.CLASS_NAME,
                            token_id=token_id
                        ))
                else:
                    token_id = self.vocab.add_token(component)
                    tokens.append(Token(
                        text=component,
                        token_type=TokenType.PACKAGE_NAME,
                        token_id=token_id
                    ))
            
            # Tokenizar nombre del método
            for sub_token in self._split_camel_case(method_name):
                token_id = self.vocab.add_token(sub_token)
                tokens.append(Token(
                    text=sub_token,
                    token_type=TokenType.METHOD_NAME,
                    token_id=token_id
                ))
        else:
            # Solo es un nombre simple
            for sub_token in self._split_camel_case(api):
                token_id = self.vocab.add_token(sub_token)
                tokens.append(Token(
                    text=sub_token,
                    token_type=TokenType.METHOD_NAME,
                    token_id=token_id
                ))
        
        return tokens
    
    def tokenize_flow(
        self,
        source: str,
        sink: str,
        category: Optional[str] = None,
        risk_level: Optional[str] = None,
        permissions: Optional[List[str]] = None
    ) -> TokenizedSequence:
        """
        Tokeniza un flujo source → sink completo.
        
        Esta es la función principal que prepara la entrada
        para el modelo Transformer.
        
        Formato de salida:
            [CLS] <source_tokens> [SEP] <sink_tokens> [SEP] <metadata> [PAD]...
        
        Args:
            source: API source (ej: "TelephonyManager.getDeviceId")
            sink: API sink (ej: "SmsManager.sendTextMessage")
            category: Categoría de vulnerabilidad (opcional)
            risk_level: Nivel de riesgo HIGH/MEDIUM/LOW (opcional)
            permissions: Lista de permisos involucrados (opcional)
        
        Returns:
            TokenizedSequence lista para el modelo
        
        Example:
            >>> tokenizer = AndroidCodeTokenizer()
            >>> seq = tokenizer.tokenize_flow(
            ...     source="TelephonyManager.getDeviceId",
            ...     sink="SmsManager.sendTextMessage",
            ...     category="SMS_LEAK",
            ...     risk_level="HIGH"
            ... )
            >>> seq.input_ids[:5]
            [2, 45, 67, 89, 3]  # [CLS], Telephony, Manager, ..., [SEP]
        """
        all_tokens = []
        input_ids = []
        token_type_ids = []  # 0 para source, 1 para sink
        
        # 1. Token [CLS] al inicio
        cls_token = Token(
            text="[CLS]",
            token_type=TokenType.SPECIAL,
            token_id=self.vocab.cls_token_id
        )
        all_tokens.append(cls_token)
        input_ids.append(self.vocab.cls_token_id)
        token_type_ids.append(0)
        
        # 2. Tokenizar SOURCE
        source_tokens = self._tokenize_api_name(source)
        for i, token in enumerate(source_tokens):
            token.token_type = TokenType.SOURCE_API
            token.position = len(all_tokens)
            all_tokens.append(token)
            input_ids.append(token.token_id)
            token_type_ids.append(0)  # Tipo 0 = source
        
        # 3. Token [SEP] para separar source y sink
        sep_token = Token(
            text="[SEP]",
            token_type=TokenType.SPECIAL,
            token_id=self.vocab.sep_token_id
        )
        all_tokens.append(sep_token)
        input_ids.append(self.vocab.sep_token_id)
        token_type_ids.append(0)
        
        # 4. Token [FLOW] para indicar dirección
        flow_token = Token(
            text="[FLOW]",
            token_type=TokenType.FLOW_ARROW,
            token_id=self.vocab.SPECIAL_TOKENS["[FLOW]"]
        )
        all_tokens.append(flow_token)
        input_ids.append(flow_token.token_id)
        token_type_ids.append(1)  # Tipo 1 = transición a sink
        
        # 5. Tokenizar SINK
        sink_tokens = self._tokenize_api_name(sink)
        for i, token in enumerate(sink_tokens):
            token.token_type = TokenType.SINK_API
            token.position = len(all_tokens)
            all_tokens.append(token)
            input_ids.append(token.token_id)
            token_type_ids.append(1)  # Tipo 1 = sink
        
        # 6. Token [SEP] final
        all_tokens.append(sep_token)
        input_ids.append(self.vocab.sep_token_id)
        token_type_ids.append(1)
        
        # 7. Añadir metadata si existe
        if category:
            cat_token = Token(
                text=category,
                token_type=TokenType.CATEGORY,
                token_id=self.vocab.add_token(category)
            )
            all_tokens.append(cat_token)
            input_ids.append(cat_token.token_id)
            token_type_ids.append(1)
        
        if risk_level:
            risk_map = {
                "HIGH": "[HIGH_RISK]",
                "MEDIUM": "[MED_RISK]",
                "LOW": "[LOW_RISK]"
            }
            risk_text = risk_map.get(risk_level.upper(), "[MED_RISK]")
            risk_token = Token(
                text=risk_text,
                token_type=TokenType.RISK_LEVEL,
                token_id=self.vocab.SPECIAL_TOKENS.get(risk_text, self.vocab.unk_token_id)
            )
            all_tokens.append(risk_token)
            input_ids.append(risk_token.token_id)
            token_type_ids.append(1)
        
        if permissions:
            for perm in permissions[:3]:  # Máximo 3 permisos
                # Extraer solo el nombre del permiso
                perm_name = perm.split('.')[-1] if '.' in perm else perm
                perm_token = Token(
                    text=perm_name,
                    token_type=TokenType.PERMISSION,
                    token_id=self.vocab.add_token(perm_name)
                )
                all_tokens.append(perm_token)
                input_ids.append(perm_token.token_id)
                token_type_ids.append(1)
        
        # Guardar longitud real antes del padding
        real_length = len(input_ids)
        
        # 8. Truncar si excede max_length
        if len(input_ids) > self.max_length:
            input_ids = input_ids[:self.max_length]
            token_type_ids = token_type_ids[:self.max_length]
            all_tokens = all_tokens[:self.max_length]
            real_length = self.max_length
        
        # 9. Padding hasta max_length
        padding_length = self.max_length - len(input_ids)
        attention_mask = [1] * len(input_ids) + [0] * padding_length
        input_ids = input_ids + [self.vocab.pad_token_id] * padding_length
        token_type_ids = token_type_ids + [0] * padding_length
        
        return TokenizedSequence(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
            tokens=all_tokens,
            real_length=real_length
        )
    
    def batch_tokenize_flows(
        self,
        flows: List[Dict[str, Any]]
    ) -> List[TokenizedSequence]:
        """
        Tokeniza múltiples flujos en batch.
        
        Args:
            flows: Lista de diccionarios con keys:
                   'source', 'sink', 'category', 'risk_level', 'permissions'
        
        Returns:
            Lista de TokenizedSequence
        
        Example:
            >>> flows = [
            ...     {"source": "getDeviceId", "sink": "sendTextMessage"},
            ...     {"source": "getLocation", "sink": "openConnection"}
            ... ]
            >>> sequences = tokenizer.batch_tokenize_flows(flows)
        """
        return [
            self.tokenize_flow(
                source=f.get("source", ""),
                sink=f.get("sink", ""),
                category=f.get("category"),
                risk_level=f.get("risk_level"),
                permissions=f.get("permissions")
            )
            for f in flows
        ]
    
    def decode(self, token_ids: List[int]) -> str:
        """
        Decodifica IDs de tokens a texto.
        
        Args:
            token_ids: Lista de IDs numéricos
            
        Returns:
            Texto reconstruido
        """
        tokens = [self.vocab.get_token(tid) for tid in token_ids]
        # Filtrar tokens especiales de padding
        tokens = [t for t in tokens if t != "[PAD]"]
        return " ".join(tokens)


# Función de utilidad para crear tokenizador con configuración por defecto
def create_default_tokenizer(max_length: int = 256) -> AndroidCodeTokenizer:
    """
    Crea un tokenizador con configuración optimizada para Android.
    
    Args:
        max_length: Longitud máxima de secuencia
        
    Returns:
        AndroidCodeTokenizer configurado
    """
    return AndroidCodeTokenizer(max_length=max_length)

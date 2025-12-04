"""
Interfaz Web - Sistema de Deteccion de Vulnerabilidades Android
================================================================

Interfaz grafica usando Streamlit para analizar APKs de forma interactiva.

Uso:
    streamlit run app.py

Autor: Tesis - Deteccion de Vulnerabilidades Android
"""

import os
import sys
import tempfile
import time
from pathlib import Path
from datetime import datetime

# Configurar paths antes de importar modulos locales
ROOT_DIR = Path(__file__).parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR / "scripts"))

# Suprimir logs
os.environ['LOGURU_LEVEL'] = 'ERROR'

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

# Configuracion de pagina
st.set_page_config(
    page_title="Detector de Vulnerabilidades Android",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS personalizado
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .vuln-critical { background-color: #dc3545; color: white; padding: 5px 10px; border-radius: 5px; }
    .vuln-high { background-color: #fd7e14; color: white; padding: 5px 10px; border-radius: 5px; }
    .vuln-medium { background-color: #ffc107; color: black; padding: 5px 10px; border-radius: 5px; }
    .vuln-low { background-color: #28a745; color: white; padding: 5px 10px; border-radius: 5px; }
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
    }
</style>
""", unsafe_allow_html=True)


def load_analyzer():
    """Carga el analizador de APKs."""
    try:
        from analyze_apk import APKAnalyzer, generate_html_report, generate_json_report
        return APKAnalyzer(), generate_html_report, generate_json_report
    except ImportError as e:
        st.error(f"Error importando analizador: {e}")
        return None, None, None


def render_header():
    """Renderiza el encabezado."""
    st.markdown('<p class="main-header">🛡️ Detector de Vulnerabilidades Android</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Sistema de análisis de seguridad basado en Machine Learning</p>', unsafe_allow_html=True)


def render_sidebar():
    """Renderiza la barra lateral."""
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/android-os.png", width=80)
        st.title("Configuración")
        
        st.markdown("---")
        
        st.markdown("### 📊 Sobre el Sistema")
        st.info("""
        Este sistema utiliza:
        - 🤖 Transformer Neural Network
        - 📱 Análisis de Taint Flow
        - 🔍 93% F1-Score
        """)
        
        st.markdown("---")
        
        st.markdown("### 📁 Formatos de Reporte")
        report_format = st.selectbox(
            "Formato de exportación:",
            ["HTML", "JSON", "Texto"]
        )
        
        st.markdown("---")
        
        st.markdown("### ℹ️ Información")
        st.caption("Versión: 1.0.0")
        st.caption("Modelo: Transformer v1")
        st.caption(f"Fecha: {datetime.now().strftime('%Y-%m-%d')}")
        
        return report_format


def render_upload_section():
    """Renderiza la sección de carga de archivos."""
    st.markdown("## 📤 Cargar APK para Análisis")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        uploaded_file = st.file_uploader(
            "Arrastra y suelta un archivo APK aquí",
            type=['apk'],
            help="Sube un archivo APK de Android para analizar sus vulnerabilidades"
        )
        
        if uploaded_file:
            st.success(f"✅ Archivo cargado: **{uploaded_file.name}**")
            st.caption(f"Tamaño: {uploaded_file.size / 1024:.1f} KB")
    
    return uploaded_file


def render_analysis_progress():
    """Muestra el progreso del análisis."""
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    steps = [
        ("Extrayendo metadata del APK...", 20),
        ("Analizando permisos...", 40),
        ("Extrayendo flujos de datos...", 70),
        ("Clasificando vulnerabilidades...", 90),
        ("Generando reporte...", 100)
    ]
    
    for text, progress in steps:
        status_text.text(text)
        progress_bar.progress(progress)
        time.sleep(0.5)
    
    status_text.text("✅ Análisis completado!")
    time.sleep(0.3)
    progress_bar.empty()
    status_text.empty()


def render_metrics(report):
    """Renderiza las métricas principales."""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🎯 Score de Riesgo",
            value=f"{report.vulnerability_score:.0f}/100",
            delta="Alto" if report.vulnerability_score > 50 else "Bajo",
            delta_color="inverse"
        )
    
    with col2:
        st.metric(
            label="🔴 Vulnerabilidades",
            value=len(report.vulnerabilities),
            delta=f"{report.summary.get('by_severity', {}).get('CRITICO', 0)} críticas"
        )
    
    with col3:
        st.metric(
            label="📊 Flujos Analizados",
            value=report.total_flows_analyzed
        )
    
    with col4:
        st.metric(
            label="⚠️ Permisos Peligrosos",
            value=len(report.dangerous_permissions)
        )


def render_risk_gauge(score):
    """Renderiza el medidor de riesgo."""
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Score de Vulnerabilidad", 'font': {'size': 24}},
        delta={'reference': 50, 'increasing': {'color': "red"}, 'decreasing': {'color': "green"}},
        gauge={
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': "darkblue"},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 25], 'color': '#28a745'},
                {'range': [25, 50], 'color': '#ffc107'},
                {'range': [50, 75], 'color': '#fd7e14'},
                {'range': [75, 100], 'color': '#dc3545'}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': score
            }
        }
    ))
    
    fig.update_layout(height=300, margin=dict(l=20, r=20, t=50, b=20))
    return fig


def render_severity_chart(report):
    """Renderiza gráfico de severidades."""
    severity_data = report.summary.get('by_severity', {})
    
    if not any(severity_data.values()):
        return None
    
    df = pd.DataFrame({
        'Severidad': list(severity_data.keys()),
        'Cantidad': list(severity_data.values())
    })
    
    colors = {'CRITICO': '#dc3545', 'ALTO': '#fd7e14', 'MEDIO': '#ffc107', 'BAJO': '#28a745'}
    df['Color'] = df['Severidad'].map(colors)
    
    fig = px.bar(
        df,
        x='Severidad',
        y='Cantidad',
        color='Severidad',
        color_discrete_map=colors,
        title='Vulnerabilidades por Severidad'
    )
    
    fig.update_layout(showlegend=False, height=300)
    return fig


def render_vuln_types_chart(report):
    """Renderiza gráfico de tipos de vulnerabilidad."""
    type_data = report.summary.get('by_type', {})
    
    if not type_data:
        return None
    
    df = pd.DataFrame({
        'Tipo': list(type_data.keys()),
        'Cantidad': list(type_data.values())
    })
    
    fig = px.pie(
        df,
        values='Cantidad',
        names='Tipo',
        title='Distribución por Tipo de Vulnerabilidad',
        hole=0.4
    )
    
    fig.update_layout(height=300)
    return fig


def render_apk_info(report):
    """Renderiza información del APK."""
    st.markdown("### 📱 Información del APK")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"""
        | Campo | Valor |
        |-------|-------|
        | **Paquete** | `{report.package_name}` |
        | **Versión** | {report.version_name} ({report.version_code}) |
        | **SDK Mínimo** | API {report.min_sdk} |
        | **SDK Objetivo** | API {report.target_sdk} |
        """)
    
    with col2:
        st.markdown(f"""
        | Campo | Valor |
        |-------|-------|
        | **Tamaño** | {report.file_size / 1024:.1f} KB |
        | **SHA256** | `{report.file_hash[:16]}...` |
        | **Análisis** | {report.analysis_duration_ms} ms |
        """)


def render_permissions(report):
    """Renderiza los permisos."""
    st.markdown("### 🔐 Permisos Solicitados")
    
    if report.dangerous_permissions:
        st.warning(f"⚠️ Se encontraron **{len(report.dangerous_permissions)}** permisos peligrosos")
        
        for perm in report.dangerous_permissions:
            short_name = perm.split('.')[-1]
            st.markdown(f"- 🔴 `{short_name}`")
    else:
        st.success("✅ No se encontraron permisos peligrosos")
    
    with st.expander("Ver todos los permisos"):
        for perm in report.permissions:
            short_name = perm.split('.')[-1]
            is_dangerous = perm in report.dangerous_permissions
            icon = "🔴" if is_dangerous else "⚪"
            st.markdown(f"{icon} `{short_name}`")


def render_vulnerabilities(report):
    """Renderiza las vulnerabilidades encontradas."""
    st.markdown("### 🔍 Vulnerabilidades Detectadas")
    
    if not report.vulnerabilities:
        st.success("✅ ¡No se encontraron vulnerabilidades!")
        st.balloons()
        return
    
    severity_colors = {
        "CRITICO": "🔴",
        "ALTO": "🟠", 
        "MEDIO": "🟡",
        "BAJO": "🟢"
    }
    
    for i, vuln in enumerate(report.vulnerabilities):
        icon = severity_colors.get(vuln.severity, "⚪")
        
        with st.expander(f"{icon} [{vuln.vuln_id}] {vuln.name} - **{vuln.severity}**", expanded=(i == 0)):
            
            # Info principal
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"**CWE:** {vuln.cwe}")
                st.markdown(f"**OWASP:** {vuln.owasp}")
                st.markdown(f"**Confianza:** {vuln.confidence*100:.0f}%")
            
            with col2:
                st.markdown(f"**Nivel de Riesgo:** {vuln.risk_level}")
            
            st.markdown("---")
            
            # Descripción
            st.markdown("#### 📝 Descripción")
            st.info(vuln.description)
            
            # Ubicación
            st.markdown("#### 📍 Ubicación en el Código")
            st.code(f"""
Source: {vuln.source_class}.{vuln.source_method}()
        API: {vuln.source_api}

Sink:   {vuln.sink_class}.{vuln.sink_method}()
        API: {vuln.sink_api}
            """, language="java")
            
            # Riesgo
            st.markdown("#### ⚠️ Riesgo")
            st.warning(vuln.risk_explanation)
            
            # Remediación
            st.markdown("#### 🛠️ Cómo Solucionarlo")
            for j, rem in enumerate(vuln.remediation, 1):
                st.markdown(f"{j}. {rem}")
            
            # Código de ejemplo
            st.markdown("#### 💻 Ejemplo de Código Seguro")
            st.code(vuln.code_example, language="java")


def render_assessment(report):
    """Renderiza la evaluación final."""
    st.markdown("### 📋 Evaluación Final")
    
    risk_assessment = report.summary.get('risk_assessment', '')
    recommendation = report.summary.get('recommendation', '')
    
    if "CRITICO" in risk_assessment:
        st.error(f"🚨 {risk_assessment}")
    elif "ALTO" in risk_assessment:
        st.warning(f"⚠️ {risk_assessment}")
    elif "MEDIO" in risk_assessment:
        st.info(f"ℹ️ {risk_assessment}")
    else:
        st.success(f"✅ {risk_assessment}")
    
    st.markdown(f"**Recomendación:** {recommendation}")


def render_download_buttons(report, generate_html, generate_json, report_format):
    """Renderiza botones de descarga."""
    st.markdown("### 📥 Descargar Reporte")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        html_report = generate_html(report)
        st.download_button(
            label="📄 Descargar HTML",
            data=html_report,
            file_name=f"{report.apk_name}_reporte.html",
            mime="text/html"
        )
    
    with col2:
        json_report = generate_json(report)
        st.download_button(
            label="📊 Descargar JSON",
            data=json_report,
            file_name=f"{report.apk_name}_reporte.json",
            mime="application/json"
        )
    
    with col3:
        # Crear resumen de texto
        text_summary = f"""
REPORTE DE SEGURIDAD - {report.apk_name}
========================================

Paquete: {report.package_name}
Versión: {report.version_name}
Score de Riesgo: {report.vulnerability_score:.0f}/100
Vulnerabilidades: {len(report.vulnerabilities)}

Evaluación: {report.summary.get('risk_assessment', 'N/A')}
        """
        st.download_button(
            label="📝 Descargar TXT",
            data=text_summary,
            file_name=f"{report.apk_name}_resumen.txt",
            mime="text/plain"
        )


def main():
    """Función principal de la aplicación."""
    
    # Renderizar header
    render_header()
    
    # Renderizar sidebar
    report_format = render_sidebar()
    
    # Cargar analizador
    analyzer, generate_html, generate_json = load_analyzer()
    
    if analyzer is None:
        st.error("❌ No se pudo cargar el analizador. Verifica la instalación.")
        st.stop()
    
    # Sección de carga
    uploaded_file = render_upload_section()
    
    # Análisis
    if uploaded_file is not None:
        # Botón de análisis
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            analyze_button = st.button("🔍 Analizar APK", type="primary", use_container_width=True)
        
        if analyze_button:
            # Guardar archivo temporal
            with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
                tmp_file.write(uploaded_file.getbuffer())
                tmp_path = tmp_file.name
            
            try:
                # Mostrar progreso
                render_analysis_progress()
                
                # Realizar análisis
                report = analyzer.analyze(tmp_path)
                
                # Guardar en session state
                st.session_state['report'] = report
                
            except Exception as e:
                st.error(f"❌ Error durante el análisis: {str(e)}")
                st.exception(e)
            finally:
                # Limpiar archivo temporal
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
    
    # Mostrar resultados si existen
    if 'report' in st.session_state:
        report = st.session_state['report']
        
        st.markdown("---")
        st.markdown("## 📊 Resultados del Análisis")
        
        # Métricas principales
        render_metrics(report)
        
        st.markdown("---")
        
        # Gráficos
        col1, col2 = st.columns(2)
        
        with col1:
            gauge_fig = render_risk_gauge(report.vulnerability_score)
            st.plotly_chart(gauge_fig, use_container_width=True)
        
        with col2:
            severity_fig = render_severity_chart(report)
            if severity_fig:
                st.plotly_chart(severity_fig, use_container_width=True)
            else:
                types_fig = render_vuln_types_chart(report)
                if types_fig:
                    st.plotly_chart(types_fig, use_container_width=True)
        
        st.markdown("---")
        
        # Tabs para diferentes secciones
        tab1, tab2, tab3, tab4 = st.tabs([
            "📱 Info APK",
            "🔐 Permisos", 
            "🔍 Vulnerabilidades",
            "📋 Evaluación"
        ])
        
        with tab1:
            render_apk_info(report)
        
        with tab2:
            render_permissions(report)
        
        with tab3:
            render_vulnerabilities(report)
        
        with tab4:
            render_assessment(report)
        
        st.markdown("---")
        
        # Botones de descarga
        render_download_buttons(report, generate_html, generate_json, report_format)
    
    # Footer
    st.markdown("---")
    st.markdown(
        """
        <div style="text-align: center; color: #666; padding: 20px;">
            <p>🛡️ Sistema de Detección de Vulnerabilidades Android</p>
            <p>Desarrollado para Tesis - 2024</p>
        </div>
        """,
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()

# """
# Frontend Module - Streamlit-based User Interface for Network IDS
# Handles all user interactions, visualizations, and real-time monitoring
# """

# import streamlit as st
# import numpy as np
# import requests
# import pandas as pd
# import plotly.graph_objects as go
# import plotly.express as px
# from datetime import datetime, timedelta
# import time
# import json
# from typing import Dict, Optional
# import base64

# # Page Configuration
# st.set_page_config(
#     page_title="Network Intrusion Detection System",
#     page_icon="🛡️",
#     layout="wide",
#     initial_sidebar_state="expanded"
# )

# # Custom CSS
# st.markdown("""
# <style>
#     .main-header {
#         font-size: 2.5rem;
#         color: #1E88E5;
#         text-align: center;
#         margin-bottom: 1rem;
#     }
#     .metric-card {
#         background-color: #f0f2f6;
#         padding: 1rem;
#         border-radius: 10px;
#         text-align: center;
#         box-shadow: 2px 2px 5px rgba(0,0,0,0.1);
#     }
#     .malicious-alert {
#         background-color: #ff4444;
#         color: white;
#         padding: 1rem;
#         border-radius: 5px;
#         text-align: center;
#         font-weight: bold;
#     }
#     .benign-alert {
#         background-color: #00C851;
#         color: white;
#         padding: 1rem;
#         border-radius: 5px;
#         text-align: center;
#         font-weight: bold;
#     }
#     .stButton>button {
#         width: 100%;
#         background-color: #1E88E5;
#         color: white;
#         font-weight: bold;
#     }
# </style>
# """, unsafe_allow_html=True)

# # Backend API Configuration
# API_BASE_URL = "http://localhost:8000"  # FastAPI backend URL

# class IDSFrontend:
#     """Main frontend application class"""
    
#     def __init__(self):
#         self.initialize_session_state()
        
#     def initialize_session_state(self):
#         """Initialize session state variables"""
#         if 'capturing' not in st.session_state:
#             st.session_state.capturing = False
#         if 'capture_history' not in st.session_state:
#             st.session_state.capture_history = []
#         if 'current_prediction' not in st.session_state:
#             st.session_state.current_prediction = None
#         if 'alert_count' not in st.session_state:
#             st.session_state.alert_count = 0
            
#     def check_backend_health(self) -> bool:
#         """Check if backend is running"""
#         try:
#             response = requests.get(f"{API_BASE_URL}/health")
#             return response.status_code == 200
#         except:
#             return False
    
#     def start_capture(self, duration: int = 10):
#         """Start packet capture via backend"""
#         try:
#             with st.spinner(f"Capturing traffic for {duration} seconds..."):
#                 response = requests.post(
#                     f"{API_BASE_URL}/capture/start",
#                     json={"duration": duration}
#                 )
#                 if response.status_code == 200:
#                     return response.json()
#                 else:
#                     st.error(f"Backend error: {response.text}")
#                     return None
#         except Exception as e:
#             st.error(f"Failed to connect to backend: {str(e)}")
#             return None
    
#     def get_prediction(self, features: list) -> Optional[Dict]:
#         """Get prediction from backend"""
#         try:
#             response = requests.post(
#                 f"{API_BASE_URL}/predict",
#                 json={"features": features}
#             )
#             if response.status_code == 200:
#                 return response.json()
#             else:
#                 st.error(f"Prediction error: {response.text}")
#                 return None
#         except Exception as e:
#             st.error(f"Failed to get prediction: {str(e)}")
#             return None
    
#     def get_shap_explanation(self, features: list) -> Optional[Dict]:
#         """Get SHAP explanation from backend"""
#         try:
#             response = requests.post(
#                 f"{API_BASE_URL}/explain",
#                 json={"features": features}
#             )
#             if response.status_code == 200:
#                 return response.json()
#             return None
#         except:
#             return None
    
#     def render_header(self):
#         """Render main header"""
#         col1, col2, col3 = st.columns([1, 2, 1])
#         with col2:
#             st.markdown("<h1 class='main-header'>🛡️ Network Intrusion Detection System</h1>", 
#                        unsafe_allow_html=True)
#             st.markdown("---")
    
#     def render_sidebar(self):
#         """Render sidebar with controls"""
#         with st.sidebar:
#             st.image("https://img.icons8.com/color/96/000000/security-checked--v1.png", 
#                     width=100)
#             st.title("Control Panel")
            
#             # Backend status
#             backend_healthy = self.check_backend_health()
#             if backend_healthy:
#                 st.success("✅ Backend Connected")
#             else:
#                 st.error("❌ Backend Disconnected")
#                 st.info("Start the backend server first!")
            
#             st.markdown("---")
            
#             # Capture controls
#             st.subheader("🎯 Capture Controls")
#             capture_duration = st.slider(
#                 "Capture Duration (seconds)",
#                 min_value=5,
#                 max_value=60,
#                 value=10,
#                 step=5
#             )
            
#             col1, col2 = st.columns(2)
#             with col1:
#                 if st.button("▶️ Start", use_container_width=True):
#                     st.session_state.capturing = True
                    
#             with col2:
#                 if st.button("⏹️ Stop", use_container_width=True):
#                     st.session_state.capturing = False
            
#             st.markdown("---")
            
#             # Detection settings
#             st.subheader("⚙️ Detection Settings")
#             threshold = st.slider(
#                 "Detection Threshold",
#                 min_value=0.0,
#                 max_value=1.0,
#                 value=0.5,
#                 step=0.05
#             )
            
#             enable_shap = st.checkbox("Enable SHAP Explanations", value=True)
#             auto_refresh = st.checkbox("Auto-refresh", value=False)
            
#             st.markdown("---")
            
#             # Stats summary
#             st.subheader("📊 Session Stats")
#             st.metric("Total Captures", len(st.session_state.capture_history))
#             st.metric("Alerts Triggered", st.session_state.alert_count)
            
#             return {
#                 'duration': capture_duration,
#                 'threshold': threshold,
#                 'enable_shap': enable_shap,
#                 'auto_refresh': auto_refresh
#             }
    
#     def render_metrics_dashboard(self, prediction_result: Dict = None):
#         """Render metrics dashboard"""
#         st.subheader("📊 Live Metrics")
        
#         cols = st.columns(4)
        
#         with cols[0]:
#             st.markdown("""
#             <div class='metric-card'>
#                 <h3>Status</h3>
#                 <h2>{}</h2>
#             </div>
#             """.format("🔴 Active" if st.session_state.capturing else "⚪ Idle"), 
#             unsafe_allow_html=True)
        
#         with cols[1]:
#             status = "⚠️ Threat" if prediction_result and prediction_result.get('is_malicious') else "✅ Safe"
#             st.markdown(f"""
#             <div class='metric-card'>
#                 <h3>Current Status</h3>
#                 <h2>{status}</h2>
#             </div>
#             """, unsafe_allow_html=True)
        
#         with cols[2]:
#             confidence = prediction_result.get('confidence', 0) if prediction_result else 0
#             st.markdown(f"""
#             <div class='metric-card'>
#                 <h3>Confidence</h3>
#                 <h2>{confidence:.1%}</h2>
#             </div>
#             """, unsafe_allow_html=True)
        
#         with cols[3]:
#             threat_level = "HIGH" if confidence > 0.7 else "MEDIUM" if confidence > 0.3 else "LOW"
#             color = "red" if threat_level == "HIGH" else "orange" if threat_level == "MEDIUM" else "green"
#             st.markdown(f"""
#             <div class='metric-card'>
#                 <h3>Threat Level</h3>
#                 <h2 style='color: {color};'>{threat_level}</h2>
#             </div>
#             """, unsafe_allow_html=True)
    
#     def render_prediction_results(self, prediction_result: Dict):
#         """Render prediction results with visualizations"""
        
#         # Main alert
#         if prediction_result['is_malicious']:
#             st.markdown(f"""
#             <div class='malicious-alert'>
#                 🚨 MALICIOUS TRAFFIC DETECTED!<br>
#                 Confidence: {prediction_result['confidence']:.1%}<br>
#                 Reason: {prediction_result['reason']}
#             </div>
#             """, unsafe_allow_html=True)
#             st.session_state.alert_count += 1
#         else:
#             st.markdown(f"""
#             <div class='benign-alert'>
#                 ✅ BENIGN TRAFFIC<br>
#                 Confidence: {prediction_result['confidence']:.1%}<br>
#                 Reason: {prediction_result['reason']}
#             </div>
#             """, unsafe_allow_html=True)
        
#         # Detailed metrics
#         col1, col2, col3 = st.columns(3)
#         with col1:
#             st.metric("XGBoost Probability", 
#                      f"{prediction_result['xgb_probability']:.3f}")
#         with col2:
#             st.metric("Isolation Score", 
#                      f"{prediction_result['isolation_score']:.3f}")
#         with col3:
#             st.metric("Decision", 
#                      "Malicious" if prediction_result['is_malicious'] else "Benign")
    
#     def render_shap_chart(self, shap_data: Dict):
#         """Render SHAP explanation chart"""
#         if not shap_data:
#             return
        
#         st.subheader("🔍 Feature Impact Analysis")
#         st.markdown("""
#         *This chart shows which features most influenced the model's decision:
#         - **Red bars** push toward malicious
#         - **Blue bars** push toward benign*
#         """)
        
#         # Create SHAP bar chart
#         fig = go.Figure()
        
#         shap_values = shap_data.get('shap_values', [])
#         feature_names = shap_data.get('feature_names', [])
        
#         if shap_values and feature_names:
#             # Sort by absolute value
#             sorted_indices = sorted(
#                 range(len(shap_values)),
#                 key=lambda i: abs(shap_values[i]),
#                 reverse=True
#             )[:15]  # Top 15 features
            
#             sorted_values = [shap_values[i] for i in sorted_indices]
#             sorted_names = [feature_names[i] for i in sorted_indices]
#             colors = ['red' if v > 0 else 'blue' for v in sorted_values]
            
#             fig.add_trace(go.Bar(
#                 y=sorted_names,
#                 x=sorted_values,
#                 orientation='h',
#                 marker_color=colors,
#                 text=[f'{v:.3f}' for v in sorted_values],
#                 textposition='outside'
#             ))
            
#             fig.update_layout(
#                 title="Top 15 Feature Impacts",
#                 xaxis_title="SHAP Value",
#                 yaxis_title="Features",
#                 height=500,
#                 showlegend=False
#             )
            
#             st.plotly_chart(fig, use_container_width=True)
    
#     def render_packet_timeline(self, packet_data: Dict):
#         """Render packet timeline visualization"""
#         st.subheader("⏱️ Packet Timeline")
        
#         if not packet_data or not packet_data.get('packet_sizes'):
#             st.info("No packet data available")
#             return
        
#         # Create packet timeline
#         df = pd.DataFrame({
#             'Time (s)': packet_data['packet_times'],
#             'Packet Size (bytes)': packet_data['packet_sizes'],
#             'Direction': packet_data['packet_directions']
#         })
        
#         fig = px.scatter(
#             df,
#             x='Time (s)',
#             y='Packet Size (bytes)',
#             color='Direction',
#             title='Packet Timeline',
#             color_discrete_map={'Forward': 'blue', 'Backward': 'red'}
#         )
        
#         fig.update_traces(marker=dict(size=10))
#         fig.update_layout(height=400)
        
#         st.plotly_chart(fig, use_container_width=True)
    
#     def render_packet_distributions(self, packet_data: Dict):
#         """Render packet size and IAT distributions"""
#         col1, col2 = st.columns(2)
        
#         with col1:
#             st.subheader("📦 Packet Size Distribution")
#             if packet_data and packet_data.get('packet_sizes'):
#                 fig = px.histogram(
#                     x=packet_data['packet_sizes'],
#                     nbins=30,
#                     title="Packet Size Distribution",
#                     labels={'x': 'Packet Size (bytes)'}
#                 )
#                 st.plotly_chart(fig, use_container_width=True)
        
#         with col2:
#             st.subheader("⏱️ Inter-Arrival Time Distribution")
#             if packet_data and packet_data.get('iat'):
#                 iat_ms = [i * 1000 for i in packet_data['iat']]  # Convert to ms
#                 fig = px.histogram(
#                     x=iat_ms,
#                     nbins=30,
#                     title="IAT Distribution",
#                     labels={'x': 'IAT (ms)'}
#                 )
#                 st.plotly_chart(fig, use_container_width=True)
    
#     def render_flag_distribution(self, flags: Dict):
#         """Render TCP flag distribution"""
#         st.subheader("🚩 TCP Flag Distribution")
        
#         if flags:
#             fig = px.bar(
#                 x=list(flags.keys()),
#                 y=list(flags.values()),
#                 title="TCP Flag Counts",
#                 labels={'x': 'Flag Type', 'y': 'Count'},
#                 color=list(flags.values()),
#                 color_continuous_scale='Viridis'
#             )
#             st.plotly_chart(fig, use_container_width=True)

#     # FIX: Moved render_feature_table inside the class (was incorrectly dedented)
#     def render_feature_table(self, features: list, feature_names: list):
#         """Render detailed feature table"""
#         st.subheader("📋 Extracted Features")
        
#         # Create DataFrame with proper columns
#         units = [
#             's', 'bytes', 'count', 'count', 'count', 'bytes', 'bytes', 'bytes', 'bytes',
#             'bytes', 'bytes', 'bytes/s', 'packets/s', 's', 's', 's', 's', 's', 's', 's',
#             's', 's', 's', 's', 's', 'count', 'count', 'count', 'count', 'count', 'count',
#             'bytes', 'bytes²'
#         ]
        
#         # Ensure units list matches features length
#         units = units[:len(features)]
        
#         # Pad units if features list is longer
#         while len(units) < len(features):
#             units.append('')
        
#         # Create DataFrame
#         df = pd.DataFrame({
#             'Feature': feature_names[:len(features)],
#             'Value': features,
#             'Unit': units
#         })
        
#         # Format the values for better display
#         df['Value'] = df['Value'].apply(lambda x: f"{x:.4f}")
        
#         # Simple display without styling
#         st.dataframe(
#             df,
#             use_container_width=True,
#             hide_index=True
#         )
        
#         # Add summary statistics in columns
#         col1, col2, col3 = st.columns(3)
        
#         with col1:
#             st.metric("Total Features", len(features))
#             st.metric("Zero Values", sum(1 for v in features if v == 0))
        
#         with col2:
#             non_zero = [v for v in features if v > 0]
#             if non_zero:
#                 st.metric("Mean (non-zero)", f"{np.mean(non_zero):.4f}")
#                 st.metric("Std Dev (non-zero)", f"{np.std(non_zero):.4f}")
        
#         with col3:
#             st.metric("Min Value", f"{min(features):.4f}")
#             st.metric("Max Value", f"{max(features):.4f}")
        
#         # Add color-coded alert for suspicious features
#         suspicious = []
#         for i, (name, value) in enumerate(zip(feature_names[:len(features)], features)):
#             if 'SYN' in name and value > 10:
#                 suspicious.append(f"⚠️ High SYN count: {value}")
#             elif 'RST' in name and value > 5:
#                 suspicious.append(f"⚠️ High RST count: {value}")
#             elif 'Bytes/s' in name and value > 10000:
#                 suspicious.append(f"⚠️ High data rate: {value:.2f} bytes/s")
        
#         if suspicious:
#             with st.expander("🚨 Suspicious Indicators"):
#                 for alert in suspicious:
#                     st.warning(alert)
    
#     def render_history(self):
#         """Render capture history"""
#         with st.expander("📜 Capture History"):
#             if st.session_state.capture_history:
#                 history_df = pd.DataFrame(st.session_state.capture_history)
#                 st.dataframe(history_df, use_container_width=True)
                
#                 if st.button("Clear History"):
#                     st.session_state.capture_history = []
#                     st.rerun()
#             else:
#                 st.info("No capture history yet")
    
#     def main(self):
#         """Main application entry point"""
#         self.render_header()
        
#         # Get sidebar controls
#         controls = self.render_sidebar()
        
#         # Main content area
#         if st.session_state.capturing:
#             result = self.start_capture(controls['duration'])
            
#             if result and 'features' in result:
#                 # Get prediction
#                 prediction = self.get_prediction(result['features'])
                
#                 if prediction:
#                     st.session_state.current_prediction = prediction
                    
#                     # Store in history
#                     history_entry = {
#                         'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
#                         'prediction': 'Malicious' if prediction['is_malicious'] else 'Benign',
#                         'confidence': prediction['confidence'],
#                         'xgb_prob': prediction['xgb_probability']
#                     }
#                     st.session_state.capture_history.append(history_entry)
                    
#                     # Render results
#                     self.render_metrics_dashboard(prediction)
#                     self.render_prediction_results(prediction)
                    
#                     # Tabs for detailed analysis
#                     tab1, tab2, tab3, tab4 = st.tabs(
#                         ["📊 Feature Impact", "⏱️ Timeline", "📈 Distributions", "📋 Features"]
#                     )
                    
#                     with tab1:
#                         if controls['enable_shap']:
#                             shap_data = self.get_shap_explanation(result['features'])
#                             self.render_shap_chart(shap_data)
                    
#                     with tab2:
#                         self.render_packet_timeline(result.get('packet_data', {}))
                    
#                     with tab3:
#                         self.render_packet_distributions(result.get('packet_data', {}))
                        
#                         if 'flags' in result:
#                             self.render_flag_distribution(result['flags'])
                    
#                     with tab4:
#                         feature_names = [
#                             "Duration", "Total Bytes", "Total Packets", "Fwd Packets", 
#                             "Bwd Packets", "Fwd Bytes", "Bwd Bytes", "Fwd Len Mean", 
#                             "Fwd Len Std", "Bwd Len Mean", "Bwd Len Std", "Bytes/s", 
#                             "Packets/s", "IAT Mean", "IAT Std", "IAT Max", "IAT Min",
#                             "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
#                             "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
#                             "FIN", "SYN", "RST", "PSH", "ACK", "URG", "Avg Size", "Size Var"
#                         ]
#                         self.render_feature_table(result['features'], feature_names)
                    
#                     # Export options
#                     col1, col2, col3 = st.columns(3)
#                     with col1:
#                         if st.button("📥 Export Results"):
#                             # Create export data
#                             export_data = {
#                                 'timestamp': datetime.now().isoformat(),
#                                 'prediction': prediction,
#                                 'features': result['features'],
#                                 'feature_names': feature_names
#                             }
                            
#                             # Convert to JSON string
#                             json_str = json.dumps(export_data, indent=2)
                            
#                             # Create download button
#                             b64 = base64.b64encode(json_str.encode()).decode()
#                             href = f'<a href="data:file/json;base64,{b64}" download="prediction_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json">Download JSON</a>'
#                             st.markdown(href, unsafe_allow_html=True)
                    
#                     with col2:
#                         if st.button("📊 Generate Report"):
#                             st.info("Report generation started...")
                    
#                     with col3:
#                         if st.button("🔔 Share Alert"):
#                             st.info("Alert shared to security team")
            
#             # Auto-refresh logic
#             if controls['auto_refresh']:
#                 time.sleep(5)
#                 st.rerun()
        
#         # Render history
#         self.render_history()

# # Run the application
# if __name__ == "__main__":
#     app = IDSFrontend()
#     app.main()

"""
NIDS Dashboard — Midnight Ebony × Electric Blue
Senior Full-Stack Implementation | Streamlit + Plotly
"""

import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import time
import json
import base64
import random
from typing import Dict, List, Optional

# ─────────────────────────────────────────────
#  PAGE CONFIG  (must be first Streamlit call)
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="NIDS — CyberWatch",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
#  DESIGN TOKENS
# ─────────────────────────────────────────────
COLORS = {
    "bg":        "#000000",
    "card":      "#111111",
    "border":    "#222222",
    "accent":    "#00D4FF",
    "accent_dim":"#007A99",
    "danger":    "#FF3B3B",
    "success":   "#00E676",
    "warning":   "#FFB300",
    "text":      "#FFFFFF",
    "muted":     "#A0A0A0",
}

# ─────────────────────────────────────────────
#  GLOBAL CSS
# ─────────────────────────────────────────────
GLOBAL_CSS = f"""
<style>
  /* ── Reset & base ── */
  @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500&display=swap');

  html, body, [data-testid="stAppViewContainer"] {{
      background-color: {COLORS['bg']} !important;
      font-family: 'Inter', sans-serif;
      color: {COLORS['text']};
  }}

  /* Remove default Streamlit padding */
  .block-container {{
      padding: 1.5rem 2rem 2rem 2rem !important;
      max-width: 100% !important;
  }}

  /* ── Sidebar ── */
  [data-testid="stSidebar"] {{
      background-color: #080808 !important;
      border-right: 1px solid {COLORS['border']};
  }}
  [data-testid="stSidebar"] .block-container {{
      padding: 1.5rem 1rem !important;
  }}
  [data-testid="stSidebar"] label,
  [data-testid="stSidebar"] p {{
      color: {COLORS['muted']} !important;
      font-size: 0.78rem !important;
      letter-spacing: 0.04em;
  }}

  /* ── Header glassmorphism ── */
  .glass-header {{
      background: linear-gradient(135deg, rgba(0,212,255,0.08) 0%, rgba(0,0,0,0.6) 100%);
      border: 1px solid rgba(0,212,255,0.2);
      border-radius: 16px;
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      padding: 1.4rem 2rem;
      margin-bottom: 1.5rem;
      display: flex;
      align-items: center;
      gap: 1.2rem;
      box-shadow: 0 0 40px rgba(0,212,255,0.07), inset 0 1px 0 rgba(255,255,255,0.04);
  }}
  .glass-header h1 {{
      font-family: 'Rajdhani', sans-serif;
      font-size: 2rem;
      font-weight: 700;
      color: {COLORS['text']};
      margin: 0;
      letter-spacing: 0.08em;
      text-transform: uppercase;
  }}
  .glass-header .subtitle {{
      font-size: 0.75rem;
      color: {COLORS['accent']};
      letter-spacing: 0.15em;
      text-transform: uppercase;
      font-family: 'JetBrains Mono', monospace;
  }}
  .pulse-dot {{
      width: 10px; height: 10px;
      border-radius: 50%;
      background: {COLORS['accent']};
      box-shadow: 0 0 0 0 {COLORS['accent']};
      animation: pulse 2s infinite;
      flex-shrink: 0;
  }}
  @keyframes pulse {{
      0%   {{ box-shadow: 0 0 0 0 rgba(0,212,255,0.6); }}
      70%  {{ box-shadow: 0 0 0 10px rgba(0,212,255,0); }}
      100% {{ box-shadow: 0 0 0 0 rgba(0,212,255,0); }}
  }}

  /* ── KPI Metric Cards ── */
  [data-testid="stMetric"] {{
      background-color: {COLORS['card']} !important;
      border: 1px solid {COLORS['border']} !important;
      border-radius: 10px !important;
      padding: 1rem 1.2rem !important;
      position: relative;
      overflow: hidden;
  }}
  [data-testid="stMetric"]::before {{
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 2px;
      background: linear-gradient(90deg, transparent, {COLORS['accent']}, transparent);
  }}
  [data-testid="stMetric"] label {{
      color: {COLORS['muted']} !important;
      font-size: 0.7rem !important;
      letter-spacing: 0.12em !important;
      text-transform: uppercase !important;
      font-family: 'JetBrains Mono', monospace !important;
  }}
  [data-testid="stMetricValue"] {{
      font-family: 'Rajdhani', sans-serif !important;
      font-size: 1.8rem !important;
      font-weight: 700 !important;
      color: {COLORS['text']} !important;
  }}
  [data-testid="stMetricDelta"] {{
      font-size: 0.72rem !important;
  }}

  /* ── Tabs ── */
  [data-testid="stTabs"] button {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      letter-spacing: 0.08em;
      color: {COLORS['muted']} !important;
      border-bottom: 2px solid transparent !important;
      background: transparent !important;
      padding: 0.6rem 1rem !important;
      transition: all 0.25s ease;
  }}
  [data-testid="stTabs"] button[aria-selected="true"] {{
      color: {COLORS['accent']} !important;
      border-bottom: 2px solid {COLORS['accent']} !important;
  }}
  [data-testid="stTabs"] button:hover {{
      color: {COLORS['text']} !important;
  }}

  /* ── Dataframe ── */
  [data-testid="stDataFrame"] {{
      border: 1px solid {COLORS['border']};
      border-radius: 8px;
      overflow: hidden;
  }}
  [data-testid="stDataFrame"] th {{
      background-color: #1a1a1a !important;
      color: {COLORS['accent']} !important;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
  }}
  [data-testid="stDataFrame"] tr:nth-child(even) {{
      background-color: #0d0d0d !important;
  }}
  [data-testid="stDataFrame"] tr:nth-child(odd) {{
      background-color: {COLORS['card']} !important;
  }}
  [data-testid="stDataFrame"] td {{
      color: {COLORS['text']};
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
  }}

  /* ── Expander (Alert Log) ── */
  [data-testid="stExpander"] {{
      background-color: {COLORS['card']};
      border: 1px solid {COLORS['border']};
      border-radius: 10px;
  }}
  [data-testid="stExpander"] summary {{
      color: {COLORS['muted']} !important;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      letter-spacing: 0.08em;
  }}

  /* ── Slider ── */
  [data-testid="stSlider"] [role="slider"] {{
      background-color: {COLORS['accent']} !important;
  }}
  [data-testid="stSlider"] [data-testid="stSliderTrackFill"] {{
      background-color: {COLORS['accent']} !important;
  }}

  /* ── Buttons ── */
  .stButton > button {{
      background: transparent;
      border: 1px solid {COLORS['accent']};
      color: {COLORS['accent']};
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      border-radius: 6px;
      padding: 0.45rem 1rem;
      transition: all 0.2s ease;
  }}
  .stButton > button:hover {{
      background: {COLORS['accent']};
      color: {COLORS['bg']};
      box-shadow: 0 0 20px rgba(0,212,255,0.4);
  }}

  /* ── Section labels ── */
  .section-label {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.7rem;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: {COLORS['accent']};
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
  }}
  .section-label::after {{
      content: '';
      flex: 1;
      height: 1px;
      background: linear-gradient(90deg, {COLORS['border']}, transparent);
  }}

  /* ── Alert badge ── */
  .alert-badge {{
      display: inline-block;
      padding: 2px 10px;
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.06em;
  }}
  .badge-danger  {{ background: rgba(255,59,59,0.15); color: {COLORS['danger']}; border: 1px solid rgba(255,59,59,0.3); }}
  .badge-success {{ background: rgba(0,230,118,0.12); color: {COLORS['success']}; border: 1px solid rgba(0,230,118,0.3); }}
  .badge-warning {{ background: rgba(255,179,0,0.12); color: {COLORS['warning']}; border: 1px solid rgba(255,179,0,0.3); }}

  /* ── Download button ── */
  .download-btn {{
      display: inline-block;
      padding: 0.45rem 1.4rem;
      border: 1px solid {COLORS['accent']};
      border-radius: 6px;
      color: {COLORS['accent']};
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      text-decoration: none;
      transition: all 0.2s ease;
      background: transparent;
  }}
  .download-btn:hover {{
      background: {COLORS['accent']};
      color: {COLORS['bg']};
      box-shadow: 0 0 20px rgba(0,212,255,0.4);
  }}

  /* ── Sidebar health bar ── */
  .health-bar-wrap {{
      background: {COLORS['border']};
      border-radius: 4px;
      height: 6px;
      width: 100%;
      overflow: hidden;
      margin-top: 4px;
  }}
  .health-bar-fill {{
      height: 100%;
      border-radius: 4px;
      transition: width 0.6s ease;
  }}
  .status-chip {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      font-weight: 600;
      letter-spacing: 0.06em;
  }}
  .chip-online  {{ background: rgba(0,230,118,0.1); color: {COLORS['success']}; border: 1px solid rgba(0,230,118,0.25); }}
  .chip-offline {{ background: rgba(255,59,59,0.1); color: {COLORS['danger']};  border: 1px solid rgba(255,59,59,0.25); }}

  /* ── Scrollbar ── */
  ::-webkit-scrollbar {{ width: 5px; height: 5px; }}
  ::-webkit-scrollbar-track {{ background: {COLORS['bg']}; }}
  ::-webkit-scrollbar-thumb {{ background: {COLORS['border']}; border-radius: 4px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: {COLORS['accent_dim']}; }}
</style>
"""

# ─────────────────────────────────────────────
#  PLOTLY DARK TEMPLATE OVERRIDE
# ─────────────────────────────────────────────
PLOTLY_LAYOUT = dict(
    template="plotly_dark",
    paper_bgcolor="#111111",
    plot_bgcolor="#111111",
    font=dict(family="JetBrains Mono, monospace", color=COLORS["muted"], size=11),
    margin=dict(l=12, r=12, t=40, b=12),
    xaxis=dict(gridcolor="#1e1e1e", zerolinecolor="#222222"),
    yaxis=dict(gridcolor="#1e1e1e", zerolinecolor="#222222"),
)


# ─────────────────────────────────────────────────────────────────
#  DATA HELPERS  (replace with real backend calls as needed)
# ─────────────────────────────────────────────────────────────────
def _mock_traffic_series(n: int = 60) -> pd.DataFrame:
    """Simulate 60-second rolling packet traffic."""
    now = datetime.now()
    times = [now - timedelta(seconds=n - i) for i in range(n)]
    fwd   = np.abs(np.random.normal(300, 80, n) + np.sin(np.linspace(0, 4 * np.pi, n)) * 60)
    bwd   = np.abs(np.random.normal(180, 50, n) + np.cos(np.linspace(0, 4 * np.pi, n)) * 40)
    return pd.DataFrame({"time": times, "Forward (pkts/s)": fwd, "Backward (pkts/s)": bwd})


def _mock_shap() -> Dict:
    names = [
        "Fwd Pkt Len Mean", "Bwd Pkt Len Std", "Flow IAT Mean",
        "SYN Flag Count",   "Bytes/s",          "RST Flag Count",
        "ACK Flag Count",   "Fwd IAT Std",       "Bwd Pkt Count",
        "Flow Duration",    "Pkt Size Avg",      "URG Flag Count",
    ]
    vals = np.random.uniform(-0.6, 0.6, len(names)).tolist()
    return {"feature_names": names, "shap_values": vals}


def _mock_prediction() -> Dict:
    is_mal  = random.random() > 0.55
    xgb_p   = random.uniform(0.62, 0.97) if is_mal else random.uniform(0.05, 0.38)
    iso_s   = random.uniform(-0.45, -0.1) if is_mal else random.uniform(-0.05, 0.3)
    conf    = abs(xgb_p - 0.5) * 2
    return {
        "is_malicious":    is_mal,
        "confidence":      conf,
        "xgb_probability": xgb_p,
        "isolation_score": iso_s,
        "reason": "XGBoost anomaly + Isolation Forest outlier detected" if is_mal else "Flow within normal statistical bounds",
        "attack_type": random.choice(["DDoS", "Port Scan", "Brute Force"]) if is_mal else "—",
    }


def _mock_features() -> List[float]:
    return [round(random.uniform(0, 1000), 4) for _ in range(33)]


def _build_download_link(data: dict) -> str:
    json_bytes = json.dumps(data, indent=2, default=str).encode()
    b64        = base64.b64encode(json_bytes).decode()
    fname      = f"nids_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return (
        f'<a class="download-btn" href="data:file/json;base64,{b64}" download="{fname}">'
        f'⬇ Download Report</a>'
    )


# ─────────────────────────────────────────────
#  MAIN APP CLASS
# ─────────────────────────────────────────────
class NIDSDashboard:
    """Class-based NIDS dashboard application."""

    FEATURE_NAMES = [
        "Duration", "Total Bytes", "Total Packets", "Fwd Packets",
        "Bwd Packets", "Fwd Bytes", "Bwd Bytes", "Fwd Len Mean",
        "Fwd Len Std", "Bwd Len Mean", "Bwd Len Std", "Bytes/s",
        "Packets/s", "IAT Mean", "IAT Std", "IAT Max", "IAT Min",
        "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
        "FIN", "SYN", "RST", "PSH", "ACK", "URG", "Avg Size", "Size Var",
    ]

    # ── lifecycle ──────────────────────────────
    def __init__(self):
        self._init_session()
        st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

    def _init_session(self):
        defaults = {
            "capturing":      False,
            "alert_count":    0,
            "capture_history": [],
            "prediction":     None,
            "traffic_df":     _mock_traffic_series(),
        }
        for k, v in defaults.items():
            if k not in st.session_state:
                st.session_state[k] = v

    # ── public entry ──────────────────────────
    def run(self):
        self._render_sidebar()
        self._render_header()
        self._render_kpi_ribbon()
        self._render_main_tabs()
        self._render_alert_log()

    # ── sidebar ───────────────────────────────
    def _render_sidebar(self):
        with st.sidebar:
            st.markdown(
                '<p style="font-family:\'Rajdhani\',sans-serif;font-size:1.3rem;'
                'font-weight:700;letter-spacing:0.12em;color:#00D4FF;'
                'text-transform:uppercase;margin-bottom:0.2rem;">⚡ CyberWatch</p>'
                '<p style="font-size:0.65rem;color:#555;font-family:\'JetBrains Mono\',monospace;'
                'letter-spacing:0.1em;margin-bottom:1.2rem;">NIDS v2.4.1</p>',
                unsafe_allow_html=True
            )

            # Backend status
            backend_ok = self._check_backend()
            chip_cls   = "chip-online" if backend_ok else "chip-offline"
            chip_dot   = "●" if backend_ok else "●"
            chip_lbl   = "BACKEND ONLINE" if backend_ok else "BACKEND OFFLINE"
            st.markdown(
                f'<span class="status-chip {chip_cls}">{chip_dot} {chip_lbl}</span>',
                unsafe_allow_html=True
            )
            st.markdown("<br>", unsafe_allow_html=True)

            # ── Capture Controls ──
            st.markdown('<div class="section-label">⊞ Capture Controls</div>', unsafe_allow_html=True)
            duration  = st.slider("Duration (sec)", 5, 60, 10, 5)
            threshold = st.slider("Detection Threshold", 0.0, 1.0, 0.5, 0.05)
            enable_shap    = st.checkbox("SHAP Explanations", value=True)
            auto_refresh   = st.checkbox("Auto-refresh (5s)", value=False)

            c1, c2 = st.columns(2)
            with c1:
                if st.button("▶ Start", use_container_width=True):
                    st.session_state.capturing = True
            with c2:
                if st.button("■ Stop", use_container_width=True):
                    st.session_state.capturing = False

            st.markdown("---")

            # ── System Health ──
            st.markdown('<div class="section-label">◈ System Health</div>', unsafe_allow_html=True)
            self._health_bar("CPU",     random.randint(20, 85))
            self._health_bar("Memory",  random.randint(35, 70))
            self._health_bar("Packets", random.randint(10, 95))

            st.markdown("---")
            st.markdown(
                '<p style="font-size:0.62rem;color:#333;font-family:\'JetBrains Mono\','
                'monospace;text-align:center;">© 2025 CyberWatch Systems</p>',
                unsafe_allow_html=True
            )

            # trigger capture cycle
            if st.session_state.capturing:
                pred     = _mock_prediction()
                feats    = _mock_features()
                st.session_state.prediction = pred
                st.session_state.traffic_df = _mock_traffic_series()
                if pred["is_malicious"]:
                    st.session_state.alert_count += 1
                    st.session_state.capture_history.append({
                        "Timestamp": datetime.now().strftime("%H:%M:%S"),
                        "Type":      pred["attack_type"],
                        "XGB Prob":  f"{pred['xgb_probability']:.3f}",
                        "ISO Score": f"{pred['isolation_score']:.3f}",
                        "Status":    "MALICIOUS",
                    })
                if auto_refresh:
                    time.sleep(5)
                    st.rerun()

            return {"duration": duration, "threshold": threshold,
                    "enable_shap": enable_shap, "auto_refresh": auto_refresh}

    def _health_bar(self, label: str, pct: int):
        color = (COLORS["success"] if pct < 50
                 else COLORS["warning"] if pct < 80
                 else COLORS["danger"])
        st.markdown(
            f'<p style="font-family:\'JetBrains Mono\',monospace;font-size:0.68rem;'
            f'color:{COLORS["muted"]};margin-bottom:2px;">{label} — {pct}%</p>'
            f'<div class="health-bar-wrap">'
            f'<div class="health-bar-fill" style="width:{pct}%;background:{color};"></div>'
            f'</div><br>',
            unsafe_allow_html=True
        )

    # ── header ────────────────────────────────
    def _render_header(self):
        pred   = st.session_state.prediction
        status = "MONITORING" if st.session_state.capturing else "STANDBY"
        st.markdown(
            f'<div class="glass-header">'
            f'  <div class="pulse-dot"></div>'
            f'  <div>'
            f'    <div class="subtitle">Network Intrusion Detection System</div>'
            f'    <h1>CyberWatch Dashboard</h1>'
            f'  </div>'
            f'  <div style="margin-left:auto;text-align:right;">'
            f'    <div style="font-family:\'JetBrains Mono\',monospace;font-size:0.68rem;'
            f'color:{COLORS["muted"]};">SYSTEM STATUS</div>'
            f'    <div style="font-family:\'Rajdhani\',sans-serif;font-size:1.1rem;'
            f'font-weight:700;color:{COLORS["accent"]};">{status}</div>'
            f'    <div style="font-family:\'JetBrains Mono\',monospace;font-size:0.62rem;'
            f'color:{COLORS["muted"]};">{datetime.now().strftime("%Y-%m-%d  %H:%M:%S")}</div>'
            f'  </div>'
            f'</div>',
            unsafe_allow_html=True
        )

    # ── KPI ribbon ────────────────────────────
    def _render_kpi_ribbon(self):
        pred   = st.session_state.prediction
        conf   = pred["confidence"] if pred else 0.0
        is_mal = pred["is_malicious"] if pred else False

        threat = ("HIGH"   if conf > 0.7
                  else "MED"    if conf > 0.35
                  else "LOW")
        status_icon = "🔴 THREAT" if is_mal else ("🟡 STANDBY" if not st.session_state.capturing else "🟢 CLEAR")

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("⚡ Status", status_icon)
        with c2:
            st.metric("☣ Threat Level", threat,
                      delta="↑ elevated" if threat == "HIGH" else None,
                      delta_color="inverse")
        with c3:
            st.metric("◎ Confidence Score", f"{conf:.1%}")
        with c4:
            st.metric("⚠ Total Alerts", st.session_state.alert_count,
                      delta="+1" if is_mal and st.session_state.capturing else None,
                      delta_color="inverse")

        st.markdown("<br>", unsafe_allow_html=True)

    # ── main tabs ─────────────────────────────
    def _render_main_tabs(self):
        tab1, tab2, tab3, tab4 = st.tabs(
            ["[ Traffic Monitor ]", "[ SHAP Analysis ]", "[ Feature Table ]", "[ Prediction ]"]
        )
        with tab1:
            self._tab_traffic()
        with tab2:
            self._tab_shap()
        with tab3:
            self._tab_features()
        with tab4:
            self._tab_prediction()

    # ── tab: traffic ──────────────────────────
    def _tab_traffic(self):
        st.markdown('<div class="section-label">Real-Time Packet Traffic</div>', unsafe_allow_html=True)
        df = st.session_state.traffic_df

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df["time"], y=df["Forward (pkts/s)"],
            name="Forward", mode="lines",
            line=dict(color=COLORS["accent"], width=2),
            fill="tozeroy",
            fillcolor="rgba(0,212,255,0.06)",
        ))
        fig.add_trace(go.Scatter(
            x=df["time"], y=df["Backward (pkts/s)"],
            name="Backward", mode="lines",
            line=dict(color=COLORS["danger"], width=2),
            fill="tozeroy",
            fillcolor="rgba(255,59,59,0.05)",
        ))
        fig.update_layout(
            **PLOTLY_LAYOUT,
            title=dict(text="Packets / Second — Live Feed",
                       font=dict(family="Rajdhani, sans-serif", size=15, color=COLORS["text"])),
            legend=dict(orientation="h", y=1.12, x=0, font=dict(size=11)),
            height=320,
        )
        st.plotly_chart(fig, use_container_width=True)

        # Summary stats row
        s1, s2, s3, s4 = st.columns(4)
        fwd = df["Forward (pkts/s)"]
        bwd = df["Backward (pkts/s)"]
        with s1: st.metric("Fwd Peak",  f"{fwd.max():.0f} p/s")
        with s2: st.metric("Fwd Avg",   f"{fwd.mean():.0f} p/s")
        with s3: st.metric("Bwd Peak",  f"{bwd.max():.0f} p/s")
        with s4: st.metric("Bwd Avg",   f"{bwd.mean():.0f} p/s")

    # ── tab: SHAP ─────────────────────────────
    def _tab_shap(self):
        st.markdown('<div class="section-label">Feature Importance — SHAP Values</div>', unsafe_allow_html=True)
        shap = _mock_shap()
        vals  = shap["shap_values"]
        names = shap["feature_names"]

        order  = sorted(range(len(vals)), key=lambda i: abs(vals[i]), reverse=True)
        s_vals = [vals[i]  for i in order]
        s_names= [names[i] for i in order]
        colors = [COLORS["danger"] if v > 0 else COLORS["accent"] for v in s_vals]

        fig = go.Figure(go.Bar(
            x=s_vals,
            y=s_names,
            orientation="h",
            marker=dict(color=colors,
                        line=dict(color="rgba(255,255,255,0.05)", width=0.5)),
            text=[f"{v:+.3f}" for v in s_vals],
            textposition="outside",
            textfont=dict(size=10, color=COLORS["muted"]),
        ))
        fig.update_layout(
            **PLOTLY_LAYOUT,
            title=dict(text="SHAP Impact — Red = Malicious push · Blue = Benign push",
                       font=dict(family="Rajdhani, sans-serif", size=14, color=COLORS["text"])),
            xaxis_title="SHAP Value",
            height=420,
        )
        # Override yaxis separately to avoid duplicate keyword conflict with PLOTLY_LAYOUT
        fig.update_yaxes(autorange="reversed", tickfont=dict(size=11))
        st.plotly_chart(fig, use_container_width=True)

        st.markdown(
            '<p style="font-size:0.7rem;color:#555;font-family:\'JetBrains Mono\','
            'monospace;">Positive values push classification toward MALICIOUS. '
            'Negative values push toward BENIGN.</p>',
            unsafe_allow_html=True
        )

    # ── tab: features ─────────────────────────
    def _tab_features(self):
        st.markdown('<div class="section-label">Extracted Flow Features</div>', unsafe_allow_html=True)
        feats = _mock_features()
        units = [
            's','bytes','count','count','count','bytes','bytes','bytes','bytes',
            'bytes','bytes','bytes/s','pkts/s','s','s','s','s','s','s','s',
            's','s','s','s','s','count','count','count','count','count','count',
            'bytes','bytes²',
        ]
        df = pd.DataFrame({
            "Feature": self.FEATURE_NAMES[:len(feats)],
            "Value":   [f"{v:.4f}" for v in feats],
            "Unit":    units[:len(feats)],
            "Flag":    ["⚠" if ('SYN' in n and feats[i] > 10) or
                               ('RST' in n and feats[i] > 5)
                        else "" for i, n in enumerate(self.FEATURE_NAMES[:len(feats)])],
        })
        st.dataframe(df, use_container_width=True, hide_index=True, height=380)

        m1, m2, m3 = st.columns(3)
        non_zero   = [v for v in feats if v != 0]
        with m1: st.metric("Total Features", len(feats))
        with m2: st.metric("Non-Zero",       len(non_zero))
        with m3: st.metric("Mean (non-zero)", f"{np.mean(non_zero):.2f}" if non_zero else "—")

    # ── tab: prediction ───────────────────────
    def _tab_prediction(self):
        st.markdown('<div class="section-label">Model Prediction Output</div>', unsafe_allow_html=True)
        pred = st.session_state.prediction
        if not pred:
            st.markdown(
                '<p style="font-family:\'JetBrains Mono\',monospace;font-size:0.82rem;'
                f'color:{COLORS["muted"]};padding:2rem 0;">'
                '// No prediction yet — start capture to run inference.</p>',
                unsafe_allow_html=True
            )
            return

        is_mal = pred["is_malicious"]
        color  = COLORS["danger"] if is_mal else COLORS["success"]
        label  = "MALICIOUS TRAFFIC DETECTED" if is_mal else "BENIGN TRAFFIC CONFIRMED"
        icon   = "🚨" if is_mal else "✅"

        st.markdown(
            f'<div style="border:1px solid {color};border-radius:10px;padding:1.2rem 1.6rem;'
            f'background:{"rgba(255,59,59,0.07)" if is_mal else "rgba(0,230,118,0.06)"};">'
            f'<div style="font-family:\'Rajdhani\',sans-serif;font-size:1.4rem;font-weight:700;'
            f'color:{color};">{icon} {label}</div>'
            f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.75rem;'
            f'color:{COLORS["muted"]};margin-top:0.4rem;">{pred["reason"]}</div>'
            f'</div>',
            unsafe_allow_html=True
        )
        st.markdown("<br>", unsafe_allow_html=True)

        c1, c2, c3, c4 = st.columns(4)
        with c1: st.metric("XGBoost Prob",   f"{pred['xgb_probability']:.4f}")
        with c2: st.metric("Isolation Score", f"{pred['isolation_score']:.4f}")
        with c3: st.metric("Confidence",      f"{pred['confidence']:.1%}")
        with c4: st.metric("Attack Type",     pred["attack_type"])

        # Gauge
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=pred["xgb_probability"] * 100,
            number=dict(suffix="%", font=dict(family="Rajdhani, sans-serif",
                                              size=32, color=COLORS["text"])),
            gauge=dict(
                axis=dict(range=[0, 100], tickcolor=COLORS["muted"],
                          tickfont=dict(size=10, color=COLORS["muted"])),
                bar=dict(color=COLORS["danger"] if is_mal else COLORS["success"], thickness=0.25),
                bgcolor="#1a1a1a",
                bordercolor=COLORS["border"],
                steps=[
                    dict(range=[0, 40],  color="#0d0d0d"),
                    dict(range=[40, 70], color="#121212"),
                    dict(range=[70, 100],color="#181818"),
                ],
                threshold=dict(line=dict(color=COLORS["accent"], width=2),
                               thickness=0.8, value=50),
            ),
            title=dict(text="Malicious Probability",
                       font=dict(family="JetBrains Mono, monospace",
                                 size=12, color=COLORS["muted"])),
        ))
        fig.update_layout(**PLOTLY_LAYOUT, height=280)
        st.plotly_chart(fig, use_container_width=True)

        # Download
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            _build_download_link({"timestamp": datetime.now().isoformat(), "prediction": pred}),
            unsafe_allow_html=True
        )

    # ── alert log ─────────────────────────────
    def _render_alert_log(self):
        st.markdown("<br>", unsafe_allow_html=True)
        history = st.session_state.capture_history
        count   = len(history)
        label   = f"⚠  Alert Log — {count} event{'s' if count != 1 else ''} recorded"

        with st.expander(label, expanded=count > 0):
            if not history:
                st.markdown(
                    '<p style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;'
                    f'color:{COLORS["muted"]};">// No alerts triggered this session.</p>',
                    unsafe_allow_html=True
                )
                return

            df = pd.DataFrame(history[::-1])  # newest first
            st.dataframe(df, use_container_width=True, hide_index=True)

            c1, c2 = st.columns([1, 5])
            with c1:
                if st.button("Clear Log"):
                    st.session_state.capture_history = []
                    st.session_state.alert_count     = 0
                    st.rerun()

    # ── helpers ───────────────────────────────
    @staticmethod
    def _check_backend() -> bool:
        """Stub — replace with real health-check request."""
        return True


# ─────────────────────────────────────────────
#  ENTRYPOINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    NIDSDashboard().run()
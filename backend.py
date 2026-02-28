"""
Backend Module - FastAPI-based server for Network IDS
Handles packet capture, feature extraction, model inference, and API endpoints
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import numpy as np
import joblib
from scapy.all import sniff, TCP, IP, Raw
import threading
import asyncio
from datetime import datetime
import logging
import json
from pathlib import Path
import shap
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="Network IDS Backend", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== Pydantic Models ====================

class CaptureRequest(BaseModel):
    """Request model for starting packet capture"""
    duration: int = 10
    interface: Optional[str] = None
    filter: Optional[str] = None

class PredictionRequest(BaseModel):
    """Request model for making predictions"""
    features: List[float]

class ExplanationRequest(BaseModel):
    """Request model for SHAP explanations"""
    features: List[float]

class CaptureResponse(BaseModel):
    """Response model for capture results"""
    features: List[float]
    packet_data: Dict[str, Any]
    flags: Dict[str, int]
    timestamp: str

class PredictionResponse(BaseModel):
    """Response model for prediction results"""
    prediction: int
    confidence: float
    xgb_probability: float
    isolation_score: float
    reason: str
    is_malicious: bool

class ExplanationResponse(BaseModel):
    """Response model for SHAP explanations"""
    shap_values: List[float]
    feature_names: List[str]
    base_value: float

class HealthResponse(BaseModel):
    """Response model for health check"""
    status: str
    models_loaded: bool
    timestamp: str

# ==================== Model Manager ====================

class ModelManager:
    """Manages ML models and predictions"""
    
    def __init__(self):
        self.xgb_model = None
        self.iso_model = None
        self.feature_names = None
        self.background_data = None
        self.explainer = None
        self.load_models()
    
    def load_models(self):
        """Load trained models from disk"""
        try:
            # Load XGBoost model
            model_path = Path("production/xgb_production_v1.pkl")
            if model_path.exists():
                self.xgb_model = joblib.load(model_path)
                logger.info("XGBoost model loaded successfully")
            else:
                logger.warning(f"XGBoost model not found at {model_path}")
            
            # Load Isolation Forest model
            iso_path = Path("production/iso_production_v1.pkl")
            if iso_path.exists():
                self.iso_model = joblib.load(iso_path)
                logger.info("Isolation Forest model loaded successfully")
            
            # Load feature names
            feature_path = Path("production/feature_names.pkl")
            if feature_path.exists():
                self.feature_names = joblib.load(feature_path)
                logger.info("Feature names loaded successfully")
            else:
                # Default feature names
                self.feature_names = [
                    "Duration", "Total Bytes", "Total Packets", "Fwd Packets", 
                    "Bwd Packets", "Fwd Bytes", "Bwd Bytes", "Fwd Len Mean", 
                    "Fwd Len Std", "Bwd Len Mean", "Bwd Len Std", "Bytes/s", 
                    "Packets/s", "IAT Mean", "IAT Std", "IAT Max", "IAT Min",
                    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
                    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
                    "FIN", "SYN", "RST", "PSH", "ACK", "URG", "Avg Size", "Size Var"
                ]
            
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
    
    def predict(self, features: np.ndarray, threshold: float = 0.5) -> Dict:
        """Make prediction using ensemble of models"""
        if self.xgb_model is None or self.iso_model is None:
            raise ValueError("Models not loaded")
        
        # XGBoost prediction
        xgb_prob = self.xgb_model.predict_proba(features.reshape(1, -1))[0][1]
        
        # Isolation Forest prediction
        iso_score = self.iso_model.decision_function(features.reshape(1, -1))[0]
        
        # Combined decision logic
        if xgb_prob >= threshold:
            final_prediction = 1
            reason = f"XGBoost confidence: {xgb_prob:.3f}"
            confidence = xgb_prob
        elif iso_score < 0:
            final_prediction = 1
            reason = f"Isolation Forest anomaly score: {iso_score:.3f}"
            confidence = abs(iso_score) / (abs(iso_score) + 1)
        else:
            final_prediction = 0
            reason = "Normal traffic pattern"
            confidence = 1 - xgb_prob
        
        return {
            'prediction': final_prediction,
            'confidence': float(confidence),
            'xgb_probability': float(xgb_prob),
            'isolation_score': float(iso_score),
            'reason': reason,
            'is_malicious': final_prediction == 1
        }
    
    def explain(self, features: np.ndarray) -> Optional[Dict]:
        """Generate SHAP explanation for prediction"""
        try:
            if self.xgb_model is None:
                return None
            
            # Create explainer if not exists
            if self.explainer is None:
                self.explainer = shap.TreeExplainer(self.xgb_model)
            
            # Calculate SHAP values
            shap_values = self.explainer.shap_values(features.reshape(1, -1))
            
            return {
                'shap_values': shap_values[0].tolist(),
                'feature_names': self.feature_names,
                'base_value': float(self.explainer.expected_value)
            }
        except Exception as e:
            logger.error(f"SHAP explanation failed: {str(e)}")
            return None

# ==================== Packet Capture Engine ====================

class PacketCaptureEngine:
    """Handles live packet capture and feature extraction"""
    
    def __init__(self):
        self.captured_packets = []
        self.is_capturing = False
        self.capture_thread = None
    
    def packet_handler(self, packet):
        """Handle individual packets during capture"""
        if self.is_capturing:
            self.captured_packets.append(packet)
    
    def start_capture(self, duration: int = 10, interface: str = None, filter: str = None):
        """Start packet capture in a separate thread"""
        self.captured_packets = []
        self.is_capturing = True
        
        def capture_thread_func():
            try:
                sniff(
                    timeout=duration,
                    prn=self.packet_handler,
                    iface=interface,
                    filter=filter,
                    store=True
                )
            except Exception as e:
                logger.error(f"Capture error: {str(e)}")
            finally:
                self.is_capturing = False
        
        self.capture_thread = threading.Thread(target=capture_thread_func)
        self.capture_thread.start()
        self.capture_thread.join(timeout=duration + 2)
        
        return self.extract_features()
    
    def extract_features(self) -> Optional[Dict]:
        """Extract 33 features from captured packets"""
        # Filter TCP packets
        tcp_packets = [pkt for pkt in self.captured_packets 
                      if pkt.haslayer(TCP) and pkt.haslayer(IP)]
        
        if len(tcp_packets) == 0:
            return None
        
        # Initialize tracking variables
        first_pkt = tcp_packets[0]
        src_ip = first_pkt[IP].src
        src_port = first_pkt[TCP].sport
        
        start_time = tcp_packets[0].time
        end_time = tcp_packets[-1].time
        flow_duration = max(end_time - start_time, 1e-6)
        
        # Direction-based stats
        fwd_packets = 0
        bwd_packets = 0
        fwd_lengths = []
        bwd_lengths = []
        fwd_timestamps = []
        bwd_timestamps = []
        
        # Flag counts
        syn_count = ack_count = fin_count = rst_count = psh_count = urg_count = 0
        
        # Packet data for visualization
        packet_sizes = []
        packet_times = []
        packet_directions = []
        
        for pkt in tcp_packets:
            size = len(pkt)
            packet_sizes.append(size)
            packet_times.append(pkt.time - start_time)
            
            # Direction detection
            if pkt[IP].src == src_ip and pkt[TCP].sport == src_port:
                fwd_packets += 1
                fwd_lengths.append(size)
                fwd_timestamps.append(pkt.time)
                packet_directions.append('Forward')
            else:
                bwd_packets += 1
                bwd_lengths.append(size)
                bwd_timestamps.append(pkt.time)
                packet_directions.append('Backward')
            
            # Flag counting
            flags = pkt[TCP].flags
            if flags & 0x02: syn_count += 1
            if flags & 0x10: ack_count += 1
            if flags & 0x01: fin_count += 1
            if flags & 0x04: rst_count += 1
            if flags & 0x08: psh_count += 1
            if flags & 0x20: urg_count += 1
        
        # Calculate totals
        total_bytes = sum(len(pkt) for pkt in tcp_packets)
        total_packets = len(tcp_packets)
        
        flow_bytes_per_sec = total_bytes / flow_duration
        flow_packets_per_sec = total_packets / flow_duration
        
        # Inter-arrival times
        all_timestamps = sorted([pkt.time for pkt in tcp_packets])
        iat = np.diff(all_timestamps) if len(all_timestamps) > 1 else np.array([0])
        
        fwd_timestamps_sorted = sorted(fwd_timestamps)
        fwd_iat = np.diff(fwd_timestamps_sorted) if len(fwd_timestamps_sorted) > 1 else np.array([0])
        
        bwd_timestamps_sorted = sorted(bwd_timestamps)
        bwd_iat = np.diff(bwd_timestamps_sorted) if len(bwd_timestamps_sorted) > 1 else np.array([0])
        
        # Safe calculation helpers
        def safe_mean(x): return np.mean(x) if len(x) > 0 else 0
        def safe_std(x): return np.std(x) if len(x) > 0 else 0
        def safe_max(x): return np.max(x) if len(x) > 0 else 0
        def safe_min(x): return np.min(x) if len(x) > 0 else 0
        def safe_sum(x): return np.sum(x) if len(x) > 0 else 0
        def safe_var(x): return np.var(x) if len(x) > 0 else 0
        
        # Construct 33 features
        features = [
            flow_duration,                    # 1
            total_bytes,                       # 2
            total_packets,                      # 3
            fwd_packets,                         # 4
            bwd_packets,                         # 5
            safe_sum(fwd_lengths),               # 6
            safe_sum(bwd_lengths),               # 7
            safe_mean(fwd_lengths),              # 8
            safe_std(fwd_lengths),               # 9
            safe_mean(bwd_lengths),              # 10
            safe_std(bwd_lengths),               # 11
            flow_bytes_per_sec,                  # 12
            flow_packets_per_sec,                 # 13
            safe_mean(iat),                       # 14
            safe_std(iat),                        # 15
            safe_max(iat),                        # 16
            safe_min(iat),                        # 17
            safe_mean(fwd_iat),                   # 18
            safe_std(fwd_iat),                    # 19
            safe_max(fwd_iat),                    # 20
            safe_min(fwd_iat),                    # 21
            safe_mean(bwd_iat),                   # 22
            safe_std(bwd_iat),                    # 23
            safe_max(bwd_iat),                    # 24
            safe_min(bwd_iat),                    # 25
            fin_count,                            # 26
            syn_count,                            # 27
            rst_count,                            # 28
            psh_count,                            # 29
            ack_count,                            # 30
            urg_count,                            # 31
            safe_mean(fwd_lengths + bwd_lengths),  # 32
            safe_var(fwd_lengths + bwd_lengths)    # 33
        ]
        
        # Packet data for visualization
        packet_data = {
            'packet_sizes': packet_sizes,
            'packet_times': packet_times,
            'packet_directions': packet_directions,
            'iat': iat.tolist() if len(iat) > 0 else []
        }
        
        # Flag data
        flags = {
            'FIN': fin_count,
            'SYN': syn_count,
            'RST': rst_count,
            'PSH': psh_count,
            'ACK': ack_count,
            'URG': urg_count
        }
        
        return {
            'features': features,
            'packet_data': packet_data,
            'flags': flags,
            'timestamp': datetime.now().isoformat()
        }

# ==================== Initialize Components ====================

model_manager = ModelManager()
capture_engine = PacketCaptureEngine()

# ==================== API Endpoints ====================

@app.get("/", response_model=Dict)
async def root():
    """Root endpoint"""
    return {
        "name": "Network IDS Backend",
        "version": "1.0.0",
        "status": "operational"
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        models_loaded=model_manager.xgb_model is not None,
        timestamp=datetime.now().isoformat()
    )

@app.post("/capture/start", response_model=CaptureResponse)
async def start_capture(request: CaptureRequest):
    """Start packet capture and extract features"""
    try:
        logger.info(f"Starting capture for {request.duration} seconds")
        
        # Run capture
        result = capture_engine.start_capture(
            duration=request.duration,
            interface=request.interface,
            filter=request.filter
        )
        
        if result is None:
            raise HTTPException(
                status_code=404,
                detail="No TCP packets captured"
            )
        
        logger.info(f"Capture complete. Extracted {len(result['features'])} features")
        
        return CaptureResponse(
            features=result['features'],
            packet_data=result['packet_data'],
            flags=result['flags'],
            timestamp=result['timestamp']
        )
        
    except Exception as e:
        logger.error(f"Capture failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Capture failed: {str(e)}"
        )

@app.post("/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest):
    """Make prediction on extracted features"""
    try:
        if model_manager.xgb_model is None:
            raise HTTPException(
                status_code=503,
                detail="XGBoost model not loaded"
            )
        
        if model_manager.iso_model is None:
            raise HTTPException(
                status_code=503,
                detail="Isolation Forest model not loaded"
            )
        
        # Convert to numpy array
        features = np.array(request.features)
        
        # Validate feature count
        expected_features = model_manager.xgb_model.n_features_in_
        if len(features) != expected_features:
            raise HTTPException(
                status_code=400,
                detail=f"Expected {expected_features} features, got {len(features)}"
            )
        
        # Make prediction
        prediction = model_manager.predict(features)
        
        logger.info(f"Prediction made: {'Malicious' if prediction['is_malicious'] else 'Benign'}")
        
        return PredictionResponse(**prediction)
        
    except Exception as e:
        logger.error(f"Prediction failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {str(e)}"
        )

@app.post("/explain", response_model=ExplanationResponse)
async def explain(request: ExplanationRequest):
    """Generate SHAP explanation for features"""
    try:
        if model_manager.xgb_model is None:
            raise HTTPException(
                status_code=503,
                detail="XGBoost model not loaded"
            )
        
        # Convert to numpy array
        features = np.array(request.features)
        
        # Generate explanation
        explanation = model_manager.explain(features)
        
        if explanation is None:
            raise HTTPException(
                status_code=500,
                detail="Failed to generate explanation"
            )
        
        return ExplanationResponse(**explanation)
        
    except Exception as e:
        logger.error(f"Explanation failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Explanation failed: {str(e)}"
        )

@app.get("/model/info")
async def get_model_info():
    """Get information about loaded models"""
    try:
        info = {
            "xgb_loaded": model_manager.xgb_model is not None,
            "iso_loaded": model_manager.iso_model is not None,
            "feature_names": model_manager.feature_names,
            "num_features": len(model_manager.feature_names) if model_manager.feature_names else 0
        }
        
        if model_manager.xgb_model:
            info["xgb_feature_importance"] = model_manager.xgb_model.feature_importances_.tolist()
        
        return info
        
    except Exception as e:
        logger.error(f"Model info failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get model info: {str(e)}"
        )

@app.post("/capture/stop")
async def stop_capture():
    """Stop ongoing packet capture"""
    try:
        capture_engine.is_capturing = False
        logger.info("Capture stopped")
        return {"status": "stopped", "message": "Capture stopped successfully"}
    except Exception as e:
        logger.error(f"Stop capture failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to stop capture: {str(e)}"
        )

@app.get("/capture/status")
async def get_capture_status():
    """Get current capture status"""
    return {
        "is_capturing": capture_engine.is_capturing,
        "packets_captured": len(capture_engine.captured_packets)
    }

# ==================== Main Entry Point ====================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
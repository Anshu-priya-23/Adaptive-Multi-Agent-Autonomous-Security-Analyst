Markdown
# Adaptive Multi-Agent Autonomous Security Analyst

An enterprise-grade, event-driven SOAR (Security Orchestration, Automation, and Response) platform that ingests network logs, analyzes threats in real-time using Groq's high-speed AI inference, and broadcasts mitigation strategies to a live web dashboard via WebSockets.

## 🏗️ Architecture & Data Flow

1. **Threat Ingestion:** A Python-based SIEM emulator simulates network traffic anomalies and securely POSTs suspicious log data to the Java backend.
2. **Orchestration & Analysis:** A high-performance Java REST API intercepts the logs and routes the network context to the Groq API (Mixtral / Llama 3.1) for ultra-low-latency threat evaluation.
3. **Structured Intelligence:** The AI engine classifies the attack vector, calculates a severity score, and generates active mitigation protocols, returning a strict JSON payload.
4. **Real-Time Telemetry:** The Java backend instantly broadcasts the analyzed JSON payload to all connected administrative clients through an open WebSocket connection.
5. **Dynamic UI:** A lightweight vanilla JavaScript frontend receives the WebSocket transmission and dynamically updates the security dashboard DOM without requiring page polling.

## 💻 Tech Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend Orchestrator** | Java (Javalin) | Highly concurrent REST API and WebSocket event broadcasting. |
| **AI Inference Engine** | Groq LPU | Sub-second algorithmic processing for real-time threat analysis. |
| **SIEM Emulator** | Python 3 | Generates, structures, and transmits simulated network attacks. |
| **Frontend Dashboard** | HTML5 / Tailwind / JS | Zero-dependency, responsive interface for live security monitoring. |

## 🚀 Getting Started

### 1. Clone & Configure
Clone the repository and set up your environment variables to authenticate with Groq. Ensure your `.env` file is excluded from version control.

git clone [https://github.com/Anshu-priya-23/Adaptive-Multi-Agent-Autonomous-Security-Analyst.git](https://github.com/Anshu-priya-23/Adaptive-Multi-Agent-Autonomous-Security-Analyst.git)
cd Adaptive-Multi-Agent-Autonomous-Security-Analyst
echo "GROQ_API_KEY=your_groq_key_here" > .env

### 2. Launch the Java Orchestrator
Compile and start the Java server. This initializes both the SIEM listener endpoint (/api/analyze) and the WebSocket broadcaster (/ws/alerts).

mvn clean compile
mvn exec:java "-Dexec.mainClass=orchestrator.ThreatManager"

### 3. Serve the Frontend Dashboard
To bypass browser security restrictions on local files (file:///), serve the dashboard using a local HTTP server. Open a new terminal window:

cd frontend
python -m http.server 8000
Navigate to http://localhost:8000 in your web browser and ensure the console reports a successful WebSocket connection.

### 4. Trigger the SIEM Emulator
With the backend orchestrator running and the dashboard active, fire the mock SIEM script to simulate a network attack. The AI will analyze the payload and the UI will update instantly.

python src/python/mock_siem.py

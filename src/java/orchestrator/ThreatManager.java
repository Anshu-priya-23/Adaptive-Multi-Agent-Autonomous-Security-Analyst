package orchestrator;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class ThreatManager {

    public static void main(String[] args) {
        System.out.println("=== Adaptive Security Orchestrator Initialized ===");

        // Simulating an incoming threat alert
        String suspiciousIp = "192.168.1.10";
        System.out.println("[ALERT] Suspicious activity detected from IP: " + suspiciousIp);

        // Trigger the RAG validation process
        validateThreat(suspiciousIp);
    }

    public static void validateThreat(String ipAddress) {
        System.out.println("[ORCHESTRATOR] Asking Python AI Agent to search RAG Database for " + ipAddress + "...\n");

        try {
            // FIX: Point directly to the virtual environment's Python executable
            ProcessBuilder pb = new ProcessBuilder("venv/Scripts/python", "src/python/search_threat.py", ipAddress);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // Read the output coming back from Python
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder pythonOutput = new StringBuilder();

            while ((line = reader.readLine()) != null) {
                System.out.println("   [PYTHON AGENT] " + line);
                pythonOutput.append(line).append("\n");
            }

            process.waitFor();

            // Orchestrator decision logic based on Python's findings
            if (pythonOutput.toString().contains("EVIDENCE")) {
                System.out.println("\n[ACTION] Multi-stage attack verified based on RAG evidence. Generating report.");
            } else {
                System.out.println("\n[ACTION] No historical data found. Confidence too low.");
            }

        } catch (Exception e) {
            System.out.println("Error calling Python script: " + e.getMessage());
        }
    }
}
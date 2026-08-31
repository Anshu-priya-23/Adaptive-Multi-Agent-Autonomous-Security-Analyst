package orchestrator;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ThreatManager {

    public static void main(String[] args) {
        System.out.println("=== Adaptive Security Orchestrator Initialized ===");
        String suspiciousIp = "192.168.1.10";
        System.out.println("[ALERT] Suspicious activity detected from IP: " + suspiciousIp);
        validateThreat(suspiciousIp);
    }

    public static void validateThreat(String ipAddress) {
        System.out.println("[ORCHESTRATOR] Asking Python Agent to search RAG Database for " + ipAddress + "...\n");

        try {
            // 1. Run Python script to retrieve database logs
            ProcessBuilder pb = new ProcessBuilder("venv/Scripts/python", "src/python/search_threat.py", ipAddress);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder evidence = new StringBuilder();

            while ((line = reader.readLine()) != null) {
                System.out.println("   [PYTHON AGENT] " + line);
                if (line.contains("EVIDENCE:")) {
                    evidence.append(line).append(" | ");
                }
            }
            process.waitFor();

            // 2. If evidence is found, trigger the Java AI Engine
            if (evidence.length() > 0) {
                System.out.println("\n[ORCHESTRATOR] Evidence retrieved. Routing to Java Native AI Engine...\n");
                generateAiReport(ipAddress, evidence.toString());
            } else {
                System.out.println("\n[ACTION] No historical data found. Confidence too low.");
            }

        } catch (Exception e) {
            System.out.println("Error calling Python script: " + e.getMessage());
        }
    }

    public static void generateAiReport(String ip, String evidence) {
        try {
            // 1. Read secret API Key from .env
            String apiKey = "";
            for (String envLine : Files.readAllLines(Paths.get(".env"))) {
                if (envLine.startsWith("GOOGLE_API_KEY=")) {
                    apiKey = envLine.split("=", 2)[1].trim();
                }
            }

            // 2. Build the AI Prompt
            String prompt = "You are an expert cybersecurity analyst. Review the network logs for IP " + ip + ": "
                    + evidence
                    + " Write a concise, professional incident report including Suspected Attack Type, Severity Level, and 1 mitigation recommendation.";
            prompt = prompt.replace("\"", "\\\"").replace("\n", " ");

            String jsonBody = "{\"contents\": [{\"parts\": [{\"text\": \"" + prompt + "\"}]}]}";

            // 3. Setup HTTP Request
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(
                            "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key="
                                    + apiKey))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            // 4. Send request with automatic rate-limit retry
            int maxRetries = 3;
            for (int attempt = 1; attempt <= maxRetries; attempt++) {
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                String respBody = response.body();

                if (response.statusCode() == 200) {
                    String cleanReport = extractFieldFromJson(respBody, "text");

                    if (cleanReport != null && !cleanReport.isEmpty()) {
                        System.out.println("--- AI INCIDENT REPORT ---");
                        System.out.println(cleanReport.trim());
                    } else {
                        System.out.println("Could not parse text from response.");
                    }
                    break;

                } else if (response.statusCode() == 429 || respBody.contains("quota")) {
                    System.out.println("   [JAVA AI ENGINE] Rate limit hit. Waiting 20 seconds before attempt "
                            + (attempt + 1) + "...");
                    Thread.sleep(20000);
                } else {
                    System.out.println("API Error. Code: " + response.statusCode() + " Body: " + respBody);
                    break;
                }
            }

        } catch (Exception e) {
            System.out.println("Java AI Engine Error: " + e.getMessage());
        }
    }

    /**
     * Safely extracts and unescapes a JSON string value by key without third-party
     * dependencies.
     */
    private static String extractFieldFromJson(String json, String key) {
        String searchKey = "\"" + key + "\": \"";
        int startIndex = json.indexOf(searchKey);
        if (startIndex == -1)
            return null;

        int contentStart = startIndex + searchKey.length();
        StringBuilder sb = new StringBuilder();
        boolean isEscaping = false;

        for (int i = contentStart; i < json.length(); i++) {
            char c = json.charAt(i);

            if (isEscaping) {
                switch (c) {
                    case 'n':
                        sb.append('\n');
                        break;
                    case 't':
                        sb.append('\t');
                        break;
                    case 'r':
                        sb.append('\r');
                        break;
                    case '"':
                        sb.append('"');
                        break;
                    case '\\':
                        sb.append('\\');
                        break;
                    default:
                        sb.append('\\').append(c);
                        break;
                }
                isEscaping = false;
            } else {
                if (c == '\\') {
                    isEscaping = true;
                } else if (c == '"') {
                    break; // Proper termination of JSON string
                } else {
                    sb.append(c);
                }
            }
        }
        return sb.toString();
    }
}
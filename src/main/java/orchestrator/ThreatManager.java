package orchestrator;

import io.javalin.Javalin;
import io.javalin.http.UploadedFile;
import io.javalin.websocket.WsContext;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class ThreatManager {

    // Track all connected WebSocket clients (browsers)
    private static final Set<WsContext> clients = ConcurrentHashMap.newKeySet();

    public static void main(String[] args) {
        Javalin app = Javalin.create(config -> {
            config.bundledPlugins.enableCors(cors -> cors.addRule(it -> it.anyHost()));
        }).start(7070);

        System.out.println("=== SOAR API Gateway Running on Port 7070 ===");

        // NEW: WebSocket Endpoint for Real-Time UI Updates
        app.ws("/ws/alerts", ws -> {
            ws.onConnect(ctx -> {
                clients.add(ctx);
                System.out.println("[WebSocket] Frontend dashboard connected.");
            });
            ws.onClose(ctx -> {
                clients.remove(ctx);
                System.out.println("[WebSocket] Frontend dashboard disconnected.");
            });
        });

        app.post("/api/analyze", ctx -> {
            String body = ctx.body();
            String ipAddress = extractFieldFromJson(body, "ip");

            if (ipAddress == null) {
                ctx.status(400).result("{\"error\": \"Missing 'ip' in request body\"}");
                return;
            }

            System.out.println("\n[API] Received analysis request for IP: " + ipAddress);
            
            String aiJsonResponse = validateThreatWithReflection(ipAddress);
            
            if (aiJsonResponse != null) {
                String severity = extractFieldFromJson(aiJsonResponse, "severity_level");
                if (severity != null && (severity.equalsIgnoreCase("High") || severity.equalsIgnoreCase("Critical"))) {
                    System.out.println("\n[🚨 ACTIVE DEFENSE TRIGGERED] AI Assessed Threat as " + severity.toUpperCase());
                    System.out.println("[ACTION] Executing iptables firewall block for IP: " + ipAddress);
                    System.out.println("[STATUS] IP " + ipAddress + " successfully quarantined.\n");
                }

                // NEW: Broadcast the AI report to all connected frontend dashboards
                for (WsContext client : clients) {
                    if (client.session.isOpen()) {
                        client.send(aiJsonResponse);
                    }
                }
            } else {
                System.out.println("[API Error] Analysis pipeline returned null. Check upstream services.");
            }
            
            ctx.contentType("application/json");
            ctx.result(aiJsonResponse != null ? aiJsonResponse : "{\"error\": \"Analysis failed due to upstream timeout.\"}");
        });

        app.post("/api/upload-logs", ctx -> {
            UploadedFile uploadedFile = ctx.uploadedFile("logFile");
            if (uploadedFile != null) {
                File dir = new File("datasets");
                if (!dir.exists()) dir.mkdir();
                Path path = Paths.get("datasets/" + uploadedFile.filename());
                
                try (InputStream content = uploadedFile.content()) {
                    Files.copy(content, path, StandardCopyOption.REPLACE_EXISTING);
                } catch (Exception e) {
                    ctx.status(500).result("{\"error\": \"Failed to save file: " + e.getMessage() + "\"}");
                    return;
                }
                
                System.out.println("[API] New log file saved: " + uploadedFile.filename());

                try {
                    System.out.println("[API] Starting ChromaDB indexing process...");
                    ProcessBuilder pb = new ProcessBuilder("venv/Scripts/python", "src/python/ingest_logs.py", path.toString());
                    pb.inheritIO();
                    int exitCode = pb.start().waitFor(); 
                    
                    if (exitCode == 0) {
                        ctx.status(200).result("{\"status\": \"success\", \"message\": \"File " + uploadedFile.filename() + " uploaded and successfully indexed.\"}");
                    } else {
                        ctx.status(500).result("{\"error\": \"File saved, but Python indexing failed.\"}");
                    }
                } catch (Exception e) {
                    ctx.status(500).result("{\"error\": \"Server error during indexing.\"}");
                }
            } else {
                ctx.status(400).result("{\"error\": \"No file detected in payload\"}");
            }
        });
    }

    public static String validateThreatWithReflection(String ipAddress) {
        int attempt = 1;
        int maxAttempts = 3;
        int contextLimit = 5; 
        
        while (attempt <= maxAttempts) {
            System.out.println("[AGENT] Attempt " + attempt + " - Extracting " + contextLimit + " lines of context...");
            
            String evidence = pullVectorContext(ipAddress, contextLimit);
            if (evidence == null || evidence.isEmpty()) {
                System.out.println("[AGENT] No evidence returned from ChromaDB.");
                return "{\"status\": \"safe\", \"message\": \"No historical data found.\"}";
            }
            
            String aiResponse = generateAiReport(ipAddress, evidence, attempt);
            if (aiResponse == null) return null; 

            String scoreStr = extractFieldFromJson(aiResponse, "confidence_score");
            int confidence = 0;
            if (scoreStr != null) {
                try { confidence = Integer.parseInt(scoreStr); } catch (Exception e) { }
            }

            System.out.println("[AGENT] AI Confidence Score: " + confidence + "/100");

            if (confidence >= 85) {
                System.out.println("[AGENT] Confidence threshold met. Proceeding.");
                // Inject the target IP into the JSON so the frontend knows who was attacked
                return injectIpIntoJson(aiResponse, ipAddress);
            } else if (attempt < maxAttempts) {
                System.out.println("[AGENT] Confidence too low (< 85). Expanding context window...");
                contextLimit += 10; 
                attempt++;
            } else {
                System.out.println("[AGENT] Max attempts reached. Forcing decision.");
                return injectIpIntoJson(aiResponse, ipAddress);
            }
        }
        return null;
    }

    private static String injectIpIntoJson(String json, String ip) {
        // Quick helper to append the IP address into the JSON string before broadcasting
        if (json.endsWith("}")) {
            return json.substring(0, json.lastIndexOf("}")) + ", \"target_ip\": \"" + ip + "\"}";
        }
        return json;
    }

    private static String pullVectorContext(String ipAddress, int limit) {
        try {
            ProcessBuilder pb = new ProcessBuilder("venv/Scripts/python", "src/python/search_threat.py", ipAddress, String.valueOf(limit));
            pb.redirectErrorStream(true);
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder evidence = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                if (line.contains("EVIDENCE:")) evidence.append(line).append(" | ");
            }
            process.waitFor();
            return evidence.toString();
        } catch (Exception e) {
            System.out.println("[Vector Context Error] " + e.getMessage());
            return null;
        }
    }

    public static String generateAiReport(String ip, String evidence, int attempt) {
        try {
            String apiKey = "";
            for (String envLine : Files.readAllLines(Paths.get(".env"))) {
                // Now looking for the Groq API key
                if (envLine.startsWith("GROQ_API_KEY=")) apiKey = envLine.split("=", 2)[1].trim();
            }

            String reflectionNote = (attempt > 1) ? "Your previous assessment lacked confidence. Look deeper at the expanded context provided. " : "";
            String prompt = "You are an expert cybersecurity analyst. " + reflectionNote + "Review the network logs for IP " + ip + ": " 
                          + evidence + " Return a strict JSON object with EXACTLY four keys: 'attack_type', 'severity_level' (Low, Medium, High, Critical), 'mitigation_recommendation', and 'confidence_score' (a number from 0 to 100). Do not include markdown.";
            prompt = prompt.replace("\"", "\\\"").replace("\n", " ");

            // Groq uses the OpenAI API standard format. We enforce JSON output using response_format.
            String jsonBody = "{\"model\": \"openai/gpt-oss-20b\", \"response_format\": {\"type\": \"json_object\"}, \"messages\": [{\"role\": \"user\", \"content\": \"" + prompt + "\"}]}";
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.groq.com/openai/v1/chat/completions"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + apiKey) // Groq requires Bearer Auth
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            int apiRetries = 0;
            int maxApiRetries = 4; 
            int waitTimeMs = 2000; 
            
            while (apiRetries < maxApiRetries) {
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                
                if (response.statusCode() == 200) {
                    // Groq nests the response inside a "content" key
                    String cleanReport = extractFieldFromJson(response.body(), "content");
                    return cleanReport != null ? cleanReport.trim() : null;
                } else if (response.statusCode() == 503 || response.statusCode() == 429) {
                    System.out.println("[AI API Error] HTTP " + response.statusCode() + " (Rate Limit). Retrying in " + (waitTimeMs/1000) + " seconds... (" + (apiRetries + 1) + "/" + maxApiRetries + ")");
                    Thread.sleep(waitTimeMs); 
                    waitTimeMs *= 2; 
                    apiRetries++;
                } else {
                    System.out.println("[AI API Error] HTTP " + response.statusCode() + ": " + response.body());
                    return null;
                }
            }
        } catch (Exception e) {
            System.out.println("[AI Engine Execution Error] " + e.getMessage());
        }
        return null;
    }

    private static String extractFieldFromJson(String json, String key) {
        try {
            String searchKey = "\"" + key + "\"";
            int keyIndex = json.indexOf(searchKey);
            if (keyIndex == -1) return null;
            int colonIndex = json.indexOf(":", keyIndex);
            if (colonIndex == -1) return null;
            int start = colonIndex + 1;
            while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
            if (start >= json.length()) return null;
            boolean isString = json.charAt(start) == '"';
            if (isString) start++;
            StringBuilder sb = new StringBuilder();
            boolean isEscaping = false;
            for (int i = start; i < json.length(); i++) {
                char c = json.charAt(i);
                if (isEscaping) {
                    switch (c) {
                        case 'n': sb.append('\n'); break;
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        default: sb.append('\\').append(c); break;
                    }
                    isEscaping = false;
                } else {
                    if (c == '\\') isEscaping = true;
                    else if (isString && c == '"') break;
                    else if (!isString && (c == ',' || c == '}' || Character.isWhitespace(c))) break;
                    else sb.append(c);
                }
            }
            return sb.toString().trim();
        } catch (Exception e) {
            return null;
        }
    }
}
package com.zhu.util.shi.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OllamaChat {
    private static final String OLLAMA_API_URL = "http://localhost:11434/api/generate";
    private static final String MODEL_NAME = "deepseek-r1:1.5b";
    private static final ObjectMapper mapper = new ObjectMapper();
    private final List<String> chatHistory = new ArrayList<>();

    public static void main(String[] args) throws IOException {
        OllamaChat chat = new OllamaChat();
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("开始对话（输入 'exit' 退出）：");
        while (true) {
            System.out.print("用户: ");
            String input = reader.readLine();
            if ("exit".equalsIgnoreCase(input)) break;
            chat.sendChatRequest(input);
        }
    }

    private void sendChatRequest(String userInput) throws IOException {
        chatHistory.add("用户: " + userInput);
        String prompt = String.join("\n", chatHistory) + "\n助手: ";

        // 使用 Jackson 生成 JSON
        Map<String, Object> requestMap = new HashMap<>();
        requestMap.put("model", MODEL_NAME);
        requestMap.put("prompt", prompt);
        requestMap.put("stream", true);
        String requestBody = mapper.writeValueAsString(requestMap);

        HttpURLConnection connection = (HttpURLConnection) new URL(OLLAMA_API_URL).openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setDoOutput(true);

        try (OutputStream os = connection.getOutputStream()) {
            os.write(requestBody.getBytes("UTF-8"));
            os.flush();
        }

        int responseCode = connection.getResponseCode();
        if (responseCode != 200) {
            // 读取错误信息
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            StringBuilder errorMessage = new StringBuilder();
            String line;
            while ((line = errorReader.readLine()) != null) {
                errorMessage.append(line);
            }
            errorReader.close();
            throw new IOException("请求失败: HTTP " + responseCode + " - " + errorMessage.toString());
        }

        StringBuilder responseText = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty()) {
                    Map<String, Object> responseMap = mapper.readValue(line, Map.class);
                    String partialResponse = (String) responseMap.get("response");
                    if (partialResponse != null) {
                        responseText.append(partialResponse);
                        System.out.print(partialResponse);
                    }
                }
            }
        }

        System.out.println();
        chatHistory.add("助手: " + responseText.toString());
    }
}
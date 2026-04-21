package com.waf.alert.controller;

import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.stereotype.Controller;
import org.springframework.web.util.HtmlUtils;

import java.util.HashMap;
import java.util.Map;

@Controller
public class WebSocketController {

    @MessageMapping("/alerts")
    @SendTo("/topic/alerts")
    public Map<String, Object> handleAlert(Map<String, Object> message) {
        Map<String, Object> response = new HashMap<>();
        response.put("type", "ECHO");
        response.put("message", HtmlUtils.htmlEscape(message.get("message").toString()));
        return response;
    }
}
package com.waf.gateway.service;

import com.waf.common.model.BotScore;
import com.waf.gateway.model.BotAnalysisResult;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
@Slf4j
public class BotDetectionService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${waf.bot.threshold:70}")
    private int botThreshold;

    @Value("${waf.bot.frequency-threshold:50}")
    private int frequencyThreshold;

    @Value("${waf.bot.js-challenge-enabled:true}")
    private boolean jsChallengeEnabled;

    private static final int PENALTY_SUSPICIOUS_UA = 35;
    private static final int PENALTY_KNOWN_BOT = 50;
    private static final int PENALTY_HIGH_FREQUENCY = 40;
    private static final int PENALTY_NO_JS_COOKIE = 20;
    private static final int PENALTY_NO_REFERRER = 20;
    private static final int PENALTY_HEADLESS = 30;
    private static final int PENALTY_AUTOMATED_TOOL = 50;
    private static final int PENALTY_IP_REPUTATION = 25;
    private static final int PENALTY_ANOMALOUS_HEADERS = 20;

    private static final Set<String> KNOWN_BOTS = Set.of(
            "curl", "wget", "python", "requests", "bot", "crawler",
            "spider", "scrapy", "apache-httpclient", "go-http", "httpclient",
            "httpx", "aiohttp", "urllib", "phantomjs", "selenium",
            "playwright", "puppeteer", "nightmare", "casper", "jsdom",
            "mechanize", "wet/spider", "grab", "masscan", "zmap",
            "nmap", "hydra", "nikto", "dirbuster", "gobuster"
    );

    private static final Set<String> EMPTY_USER_AGENTS = Set.of("", "null", "-", "none");

    private static final Set<String> SUSPICIOUS_PATTERNS = Set.of(
            "sqlmap", "havij", "pangolin", "bpsql", "sqli",
            "acunetix", "netsparker", "appscan", "webinspect",
            "burp", "zaproxy", "w3af", "metasploit",
            "nessus", "openvas", "qualys", "nexpose"
    );

    private static final Set<String> DATACENTER_IPS = Set.of(
            "104.", "130.", "157.", "185.", "198.", "23.", "34.", "35.",
            "40.", "45.", "52.", "54.", "64.", "65.", "66.", "67.",
            "68.", "69.", "70.", "71.", "72.", "73.", "74.", "75.",
            "76.", "77.", "78.", "79.", "8.", "80.", "81.", "82."
    );

    private static final AtomicLong ID_COUNTER = new AtomicLong(0);

    public BotDetectionService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public static String generateEventId() {
        long id = ID_COUNTER.incrementAndGet();
        long time = System.currentTimeMillis();
        return Long.toHexString(time) + "-" + Long.toHexString(id);
    }

    public BotScore analyzeBotBehavior(String ip, HttpServletRequest request) {
        BotScore score = new BotScore();

        analyzeUserAgent(request, score);
        analyzeFrequency(ip, score);
        analyzeNavigation(request, score);

        if (jsChallengeEnabled) {
            analyzeJsCookie(request, score);
        } else {
            Cookie[] cookies = request.getCookies();
            if (cookies == null || cookies.length == 0) {
                score.setJsCookiePenalty(PENALTY_NO_JS_COOKIE / 2);
            }
        }

        analyzeIpReputation(ip, score);
        analyzeHeaders(request, score);
        recordRequest(ip);

        log.debug("Bot detection for IP {}: score={}, isBot={}", ip, score.getTotalScore(), score.isBot());

        return score;
    }

    public BotAnalysisResult analyzeBotComprehensive(String ip, HttpServletRequest request) {
        BotScore score = analyzeBotBehavior(ip, request);
        
        return BotAnalysisResult.builder()
                .ip(ip)
                .score(score)
                .isBot(score.isBot())
                .threshold(botThreshold)
                .analysisTime(Instant.now())
                .build();
    }

    private void analyzeUserAgent(HttpServletRequest request, BotScore score) {
        String userAgent = request.getHeader("User-Agent");
        
        if (userAgent == null || userAgent.isEmpty()) {
            score.setUserAgentPenalty(score.getUserAgentPenalty() + PENALTY_SUSPICIOUS_UA);
            return;
        }

        String lowerUA = userAgent.toLowerCase();

        if (EMPTY_USER_AGENTS.contains(lowerUA)) {
            score.setUserAgentPenalty(score.getUserAgentPenalty() + PENALTY_SUSPICIOUS_UA);
        }

        for (String bot : KNOWN_BOTS) {
            if (lowerUA.contains(bot)) {
                score.setUserAgentPenalty(score.getUserAgentPenalty() + PENALTY_KNOWN_BOT);
                return;
            }
        }

        for (String tool : SUSPICIOUS_PATTERNS) {
            if (lowerUA.contains(tool)) {
                score.setUserAgentPenalty(score.getUserAgentPenalty() + PENALTY_AUTOMATED_TOOL);
                return;
            }
        }
    }

    private void analyzeFrequency(String ip, BotScore score) {
        int requestCount = getRequestCountLastMinute(ip);
        
        if (requestCount > frequencyThreshold) {
            score.setFrequencyPenalty(PENALTY_HIGH_FREQUENCY);
        } else if (requestCount > frequencyThreshold / 2) {
            score.setFrequencyPenalty(score.getFrequencyPenalty() + 15);
        }
    }

    private void analyzeNavigation(HttpServletRequest request, BotScore score) {
        String referer = request.getHeader("Referer");
        String origin = request.getHeader("Origin");
        boolean hasReferer = referer != null && !referer.isEmpty();
        boolean hasOrigin = origin != null && !origin.isEmpty();
        
        boolean isGetMethod = "GET".equalsIgnoreCase(request.getMethod());
        
        if (isGetMethod && !hasReferer && !hasOrigin) {
            score.setNavigationPenalty(score.getNavigationPenalty() + PENALTY_NO_REFERRER);
        }

        if (hasReferer) {
            if (referer.equals("-") || referer.equals("*") || referer.equals("/")) {
                score.setNavigationPenalty(score.getNavigationPenalty() + 10);
            }
        }
    }

    private void analyzeJsCookie(HttpServletRequest request, BotScore score) {
        Cookie[] cookies = request.getCookies();
        boolean hasJsCookie = false;
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                String name = cookie.getName();
                if (name.startsWith("X-JS-") || 
                    name.equals("jschal") || 
                    name.equals("challenge")) {
                    hasJsCookie = true;
                    
                    if (!isValidJsCookie(cookie.getValue())) {
                        hasJsCookie = false;
                    }
                    break;
                }
            }
        }
        
        if (!hasJsCookie) {
            score.setJsCookiePenalty(PENALTY_NO_JS_COOKIE);
        }
    }

    private boolean isValidJsCookie(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        return value.length() >= 10;
    }

    private void analyzeIpReputation(String ip, BotScore score) {
        if (ip == null) {
            return;
        }

        for (String prefix : DATACENTER_IPS) {
            if (ip.startsWith(prefix)) {
                score.setUserAgentPenalty(score.getUserAgentPenalty() + PENALTY_IP_REPUTATION);
                return;
            }
        }

        try {
            String reputationKey = "ip:reputation:" + ip;
            Map<Object, Object> rep = redisTemplate.opsForHash().entries(reputationKey);
            
            if (rep != null && !rep.isEmpty()) {
                Object threatCount = rep.get("threat_count");
                if (threatCount != null && Integer.parseInt(threatCount.toString()) > 5) {
                    score.setUserAgentPenalty(score.getUserAgentPenalty() + PENALTY_IP_REPUTATION);
                }
            }
        } catch (Exception e) {
            log.debug("Error checking IP reputation: {}", e.getMessage());
        }
    }

    private void analyzeHeaders(HttpServletRequest request, BotScore score) {
        int anomalyCount = 0;

        boolean hasAccept = request.getHeader("Accept") != null;
        boolean hasAcceptLanguage = request.getHeader("Accept-Language") != null;

        if (!hasAccept && !hasAcceptLanguage) {
            anomalyCount++;
        }

        String accept = request.getHeader("Accept");
        if (accept != null && accept.equals("*/*")) {
            anomalyCount++;
        }

        String secUa = request.getHeader("Sec-Ua");
        if (secUa != null && (secUa.contains("Not.A/Brand") || secUa.contains("Chromium"))) {
            anomalyCount += 2;
        }

        if (anomalyCount >= 2) {
            score.setNavigationPenalty(score.getNavigationPenalty() + PENALTY_ANOMALOUS_HEADERS);
        }
    }

    private int getRequestCountLastMinute(String ip) {
        String key = "bot:requests:" + ip;
        try {
            Long count = redisTemplate.opsForZSet().zCard(key);
            return count != null ? count.intValue() : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private void recordRequest(String ip) {
        if (ip == null) {
            return;
        }
        
        try {
            String key = "bot:requests:" + ip;
            long now = System.currentTimeMillis();
            redisTemplate.opsForZSet().add(key, String.valueOf(now), now);
            redisTemplate.expire(key, 1, TimeUnit.MINUTES);
        } catch (Exception e) {
            log.debug("Error recording request: {}", e.getMessage());
        }
    }

    public void setBotThreshold(int botThreshold) {
        this.botThreshold = botThreshold;
    }

    public void setFrequencyThreshold(int frequencyThreshold) {
        this.frequencyThreshold = frequencyThreshold;
    }

}
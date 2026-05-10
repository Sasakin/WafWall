package com.waf.gateway.service;

import com.waf.common.model.BotScore;
import com.waf.common.model.ThreatType;
import com.waf.gateway.filter.FilterResult;
import com.waf.gateway.filter.SecurityFilter;
import com.waf.gateway.util.IpUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Component
@Order(3)
@Slf4j
public class BotDetectionFilter implements SecurityFilter {

    private final BotDetectionService botDetectionService;

    public BotDetectionFilter(BotDetectionService botDetectionService) {
        this.botDetectionService = botDetectionService;
    }

    @Override
    public ThreatType getThreatType() {
        return ThreatType.BOT_DETECTED;
    }

    @Override
    public FilterResult check(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path.startsWith("/actuator")) {
            return pass();
        }
        
        String clientIp = IpUtil.getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        log.info("BotDetection: checking IP={}, UA={}", clientIp, userAgent);

        BotScore score = botDetectionService.analyzeBotBehavior(clientIp, request);

        log.info("BotDetection: score={}, isBot={}, threshold=70", score.getTotalScore(), score.isBot());

        if (score.isBot()) {
            return block("Bot detected - score: " + score.getTotalScore());
        }
        return pass();
    }
}
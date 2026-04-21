package com.waf.gateway.service;

import com.waf.common.model.BotScore;
import com.waf.common.model.ThreatType;
import com.waf.gateway.filter.FilterResult;
import com.waf.gateway.filter.SecurityFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
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
        String clientIp = request.getRemoteAddr();
        BotScore score = botDetectionService.analyzeBotBehavior(clientIp, request);

        if (score.isBot()) {
            return block("Bot detected - score: " + score.getTotalScore());
        }
        return pass();
    }
}
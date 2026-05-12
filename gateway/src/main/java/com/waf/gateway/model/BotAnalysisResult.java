package com.waf.gateway.model;

import com.waf.common.model.BotScore;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class BotAnalysisResult {
    private String ip;
    private BotScore score;
    private boolean isBot;
    private int threshold;
    private Instant analysisTime;
}

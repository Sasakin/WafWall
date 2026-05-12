package com.waf.common.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BotScore {
    private Integer userAgentPenalty = 0;
    private Integer frequencyPenalty = 0;
    private Integer navigationPenalty = 0;
    private Integer jsCookiePenalty = 0;

    public void addPenalty(int points) {
        this.userAgentPenalty += points;
    }

    public Integer getTotalScore() {
        return userAgentPenalty + frequencyPenalty + navigationPenalty + jsCookiePenalty;
    }

    public boolean isBot() {
        return getTotalScore() >= 70;
    }
}
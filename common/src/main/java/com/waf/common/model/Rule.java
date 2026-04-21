package com.waf.common.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Rule {
    private String id;
    private String pattern;
    private Integer threshold;
    private Long ttlSeconds;
    private Action action;

    public enum Action {
        BLOCK,
        THROTTLE,
        LOG
    }
}
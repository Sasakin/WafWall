package com.waf.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.util.List;

@Configuration
public class LuaScriptConfig {

    @Bean
    public DefaultRedisScript rateLimitScript() {
        DefaultRedisScript<List> script = new DefaultRedisScript<>();
        script.setLocation(new ClassPathResource("lua/rate_limit_check.lua"));
        script.setResultType(List.class);
        return script;
    }

    @Bean
    public DefaultRedisScript botRecordScript() {
        DefaultRedisScript<List> script = new DefaultRedisScript<>();
        script.setLocation(new ClassPathResource("lua/bot_record_and_count.lua"));
        script.setResultType(List.class);
        return script;
    }
}

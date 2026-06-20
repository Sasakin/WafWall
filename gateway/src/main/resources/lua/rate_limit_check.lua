-- rate_limit_check.lua
-- Atomic rate limit check: cleanup expired + count + add if allowed
-- KEYS[1] = rate_limit:<ip>:<path>
-- ARGV[1] = now (timestamp ms)
-- ARGV[2] = windowStart (now - window*1000)
-- ARGV[3] = maxRequests
-- ARGV[4] = windowSeconds (for EXPIRE)
-- Returns: {currentCount, 1=allowed/0=blocked}

redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[2])
local count = redis.call('ZCARD', KEYS[1])

if count >= tonumber(ARGV[3]) then
    return {count, 0}
end

redis.call('ZADD', KEYS[1], ARGV[1], ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[4])
return {count + 1, 1}

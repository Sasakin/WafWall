-- bot_record_and_count.lua
-- Atomic bot tracking: count existing requests, then add current one
-- KEYS[1] = bot:requests:<ip>
-- ARGV[1] = now (timestamp ms)
-- Returns: {requestCountBeforeAdding}

local count = redis.call('ZCARD', KEYS[1])
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[1])
redis.call('EXPIRE', KEYS[1], 60)
return {count}

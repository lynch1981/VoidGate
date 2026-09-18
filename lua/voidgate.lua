-- SPDX-License-Identifier: Apache-2.0

local unix = require("socket.unix")
local M = {}
local client = {}
client.__index = client

-- Keep uint64 counters as strings so Lua 5.1 / LuaJIT do not round them.
local counters = {
    rx_pkts = true, rx_bytes = true, passed = true, dropped = true,
    non_ip = true, map_full = true, parse_err = true,
}

local function request(self, cmd)
    local sock, err = unix.stream()
    if not sock then
        return nil, err
    end

    sock:settimeout(self.timeout)
    local data
    data, err = sock:connect(self.path)
    if data then
        data, err = sock:send(cmd .. "\n")
    end
    if data then
        sock:shutdown("send")
        data, err = sock:receive("*a")
    end
    sock:close()
    if not data then
        return nil, err
    end
    if data:find("^error") then
        return nil, data:gsub("\n+$", "")
    end
    return data
end

local function kv(data)
    local t = {}
    for k, v in data:gmatch("([%w_]+)=(%S+)") do
        if counters[k] then
            t[k] = v
        elseif k == "armed" then
            t[k] = v == "1"
        else
            t[k] = tonumber(v) or v
        end
    end
    return t
end

function client:status()
    local data, err = request(self, "status")
    if not data then
        return nil, err
    end
    return kv(data)
end

function client:stats()
    local data, err = request(self, "stats")
    if not data then
        return nil, err
    end
    return kv(data)
end

function client:drops()
    local data, err = request(self, "drops")
    if not data then
        return nil, err
    end

    local out = {}
    for line in data:gmatch("[^\n]+") do
        local cidr, reason, age = line:match("^(%S+) reason=(%S+) age=(%S+)$")
        if cidr then
            out[#out + 1] = {
                cidr = cidr,
                reason = tonumber(reason) or reason,
                age = tonumber(age) or age,
            }
        end
    end
    return out
end

local function commit(self, cmd)
    local data, err = request(self, cmd)
    if not data then
        return nil, err
    end
    if data ~= "ok\n" then
        return nil, "unexpected response"
    end
    return true
end

function client:arm()
    return commit(self, "arm")
end

function client:disarm()
    return commit(self, "disarm")
end

function client:reload()
    return commit(self, "reload")
end

function client:drop(cidr)
    if type(cidr) ~= "string" or cidr:find("%s") then
        return nil, "bad cidr"
    end
    return commit(self, "drop " .. cidr)
end

function client:undrop(cidr)
    if type(cidr) ~= "string" or cidr:find("%s") then
        return nil, "bad cidr"
    end
    return commit(self, "undrop " .. cidr)
end

function M.new(opt)
    opt = opt or {}
    return setmetatable({
        path = opt.path or "/run/voidgate.sock",
        timeout = opt.timeout or 1,
    }, client)
end

local default = M.new()
for _, name in ipairs({
    "status", "stats", "drops", "arm", "disarm", "drop", "undrop", "reload",
}) do
    M[name] = function(...)
        return default[name](default, ...)
    end
end

return M

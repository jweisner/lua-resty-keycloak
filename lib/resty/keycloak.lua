local require = require
local cjson = require("cjson")
local cjson_s = require("cjson.safe")
local http = require("resty.http")
local r_session = require("resty.session")
local string = string
local ipairs = ipairs
local pairs = pairs
local type = type
local ngx = ngx
local b64 = ngx.encode_base64
local unb64 = ngx.decode_base64

local log = ngx.log
local DEBUG = ngx.DEBUG
local ERROR = ngx.ERR
local WARN = ngx.WARN

local keycloak = {
    _VERSION = "0.0.1"
}

keycloak.__index = keycloak

local function load_config(config_path) {
    keycloak.config = {}
}

function keycloak.enforcer(config_path) {
    if keycloak.config == nil then
        load_config(config_path)
    end
}

function keycloak.enforce(request) {}

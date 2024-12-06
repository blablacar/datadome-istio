
local DATADOME_API_KEY = options['API_KEY']

local DATADOME_API_TIMEOUT = options['API_TIMEOUT'] or 100

local DATADOME_CLUSTER_NAME = options['DATADOME_CLUSTER_NAME'] or 'datadome'

local DATADOME_ENABLE_UNPROTECTED_CACHED_RESPONSE = options['ENABLE_UNPROTECTED_CACHED_RESPONSE'] or false

local DATADOME_ENDPOINT = options['DATADOME_ENDPOINT'] or 'api.datadome.co'

local DATADOME_TENANT_NAME = options['DATADOME_TENANT_NAME'] or 'default'

local DATADOME_URI_PATTERNS = options['URI_PATTERNS'] or {}

-- LUA doesn't support regex with logical or, only simple pattern matching
-- rewrite standard regex into array of patterns
-- /\.(avi|flv|mka|mkv|mov|mp4|mpeg|mpg|mp3|flac|ogg|ogm|opus|wav|webm|webp|bmp|gif|ico|jpeg|jpg|png|svg|svgz|swf|eot|otf|ttf|woff|woff2|css|less|js)$
local DATADOME_URI_PATTERNS_EXCLUSION = options['URI_PATTERNS_EXCLUSION'] or {
  '%.avi$',
  '%.flv$',
  '%.mka$',
  '%.mkv$',
  '%.mov$',
  '%.mp4$',
  '%.mpeg$',
  '%.mpg$',
  '%.mp3$',
  '%.flac$',
  '%.ogg$',
  '%.ogm$',
  '%.opus$',
  '%.wav$',
  '%.webm$',
  '%.webp$',
  '%.bmp$',
  '%.gif$',
  '%.ico$',
  '%.jpeg$',
  '%.jpg$',
  '%.png$',
  '%.svg$',
  '%.svgz$',
  '%.swf$',
  '%.eot$',
  '%.otf$',
  '%.ttf$',
  '%.woff$',
  '%.woff2$',
  '%.css$',
  '%.less$',
  '%.js$'
}

local DATADOME_MODULE_NAME="Envoy"

local DATADOME_MODULE_VERSION="2.1.0"

local DATADOME_REQUEST_PORT=0

local DATADOME_HEADERS_TO_REMOVE={"x-datadomeresponse", "x-datadome-headers", "x-datadome-request-headers"}

-- some helpers
local function urlencode(str)
  if str then
    str = string.gsub(str, '\n', '\r\n')
    str = string.gsub(str, '([^%w-_.~])', function(c)
                        return string.format('%%%02X', string.byte(c))
    end)
  end
  return str
end

local function stringify(params)
  if type(params) == "table" then
    local fields = {}
    for key,value in pairs(params) do
      local keyString = urlencode(tostring(key)) .. '='
      if type(value) == "table" then
        for _, v in ipairs(value) do
          table.insert(fields, keyString .. urlencode(tostring(v)))
        end
      else
        table.insert(fields, keyString .. urlencode(tostring(value)))
      end
    end
    return table.concat(fields, '&')
  end
  return ''
end

string.startswith = function(self, str)
  return self:find('^' .. str) ~= nil
end

function gethostname()
  local host = os.getenv('HOSTNAME')
  if host then
    return host
  end

  local f = io.open('/proc/sys/kernel/hostname')
  local hostname = f:read('*line') or ''
  f:close()

  return hostname
end

local hostname = gethostname()

local function getHeadersList(request_handle)
  local headers = ""
  for key, value in pairs(request_handle:headers()) do
    if not string.startswith(key, ":") then
      if string.len(headers) > 0 then
        headers = headers .. ","
      end
      headers = headers .. key
    end
  end
  return headers
end

local function getClientIdAndCookiesLength(request_handle)
  local cookie = request_handle:headers():get("cookie") or ""
  local len = string.len(cookie)
  local clientId = request_handle:headers():get("x-datadome-clientid")
  local is_client_id_from_header = false
  if clientId ~= nil then
    is_client_id_from_header = true
  elseif len > 0 then
    for k, v in string.gmatch(cookie, "([^;= ]+)=([^;$]+)") do
      if k == "datadome" then
        clientId = v
        break
      end
    end
  end
  return clientId, len, is_client_id_from_header
end

local function getAuthorizationLen(request_handle)
  return string.len(request_handle:headers():get("authorization") or "")
end

function table.removekey(tbl, key)
  local element = tbl[key]
  tbl[key] = nil
  return element
end

local function parse_xdd_header(value)
  local t = {}
  if value == nil then
    return t
  end
  for h in string.gmatch(value, "([^ ]+)") do
    t[string.lower(h)] = true
  end
  return t
end

-- @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
local cacheable_directives = {
  ["max-age"] = true,
  ["s-maxage"] = true,
  ["public"] = true,
}

-- this returns whether the response can be cached according to its cache-control header value (true if the response includes any cacheable directives)
local function is_cacheable_response(response_handle)
  local metadata = response_handle:streamInfo():dynamicMetadata():get(DATADOME_TENANT_NAME .. "cache_metadata", "cache-control")

  if not metadata then
    return false
  end

  local cacheControlValue = metadata['cache-control']

  if not cacheControlValue then
    return false
  end

  -- gmatch will split the string to extract each directive part
  -- "public, max-age=604800, stale-if-error=86400" will become
  -- public, max-age, 604800, stale-if-error, 86400
  for directive in string.gmatch(cacheControlValue, "([^,=%s]+)=?") do
    if cacheable_directives[directive] then
      return true
    end
  end

  return false
end

-- the module
function envoy_on_request(request_handle)
  local headers = request_handle:headers()

  local host = headers:get(":authority")
  local pathWithQuery = headers:get(":path")
  local path = string.gsub(pathWithQuery, "?.*", "")
  local hostWithPath = host .. path

  for _, pattern in pairs(DATADOME_URI_PATTERNS_EXCLUSION) do
    if string.match(hostWithPath, pattern) then
      return
    end
  end

  local matched = next(DATADOME_URI_PATTERNS) == nil

  for _, pattern in pairs(DATADOME_URI_PATTERNS) do
    if string.match(hostWithPath, pattern) then
      matched = true
      break
    end
  end

  if not matched then
    return
  end

  local clientId, cookieLen, is_client_id_from_header = getClientIdAndCookiesLength(request_handle)
  local datadome_payload_body = stringify(
    truncateHeaders({
      ["Key"]               = DATADOME_API_KEY,
      ["IP"]                = headers:get("x-envoy-external-address"),
      ["RequestModuleName"] = DATADOME_MODULE_NAME,
      ["ModuleVersion"]     = DATADOME_MODULE_VERSION,
      ["ServerName"]        = hostname,
      ["Port"]              = DATADOME_REQUEST_PORT,
      ["TimeRequest"]       = request_handle:timestampString(EnvoyTimestampResolution.MICROSECOND),
      ["Protocol"]          = headers:get("x-forwarded-proto"),
      ["Method"]            = headers:get(":method"),
      ["ServerHostname"]    = headers:get("host"),
      ["Request"]           = pathWithQuery,
      ["HeadersList"]       = getHeadersList(request_handle),
      ["Host"]              = headers:get("host"),
      ["From"]              = headers:get("from"),
      ["UserAgent"]         = headers:get("User-Agent"),
      ["Referer"]           = headers:get("referer"),
      ["Accept"]            = headers:get("accept"),
      ["AcceptEncoding"]    = headers:get("accept-encoding"),
      ["AcceptLanguage"]    = headers:get("accept-language"),
      ["AcceptCharset"]     = headers:get("accept-charset"),
      ["ContentType"]       = headers:get("content-type"),
      ["Origin"]            = headers:get("origin"),
      ["XForwardedForIP"]   = headers:get("x-forwarded-for"),
      ["X-Requested-With"]  = headers:get("x-requested-with"),
      ["Connection"]        = headers:get("connection"),
      ["Pragma"]            = headers:get("pragma"),
      ["CacheControl"]      = headers:get("cache-control"),
      ["CookiesLen"]        = tostring(cookieLen),
      ["AuthorizationLen"]  = tostring(getAuthorizationLen(request_handle)),
      ["PostParamLen"]      = headers:get("content-length"),
      ["ClientID"]          = clientId,
      ["Via"]               = headers:get("via"),
      ["SecCHUA"]           = headers:get("Sec-CH-UA"),
      ["SecCHUAMobile"]     = headers:get("Sec-CH-UA-Mobile"),
      ["SecCHUAPlatform"]   = headers:get("Sec-CH-UA-Platform"),
      ["SecCHUAArch"]       = headers:get("Sec-CH-UA-Arch"),
      ["SecCHUAFullVersionList"] = headers:get("Sec-CH-UA-Full-Version-List"),
      ["SecCHUAModel"]      = headers:get("Sec-CH-UA-Model"),
      ["SecCHDeviceMemory"] = headers:get("Sec-CH-Device-Memory"),
      ["SecFetchDest"]      = headers:get("Sec-Fetch-Dest"),
      ["SecFetchMode"]      = headers:get("Sec-Fetch-Mode"),
      ["SecFetchSite"]      = headers:get("Sec-Fetch-Site"),
      ["SecFetchUser"]      = headers:get("Sec-Fetch-User"),
    })
  )

  local request_header = {
    [":method"] = "POST",
    [":path"] = "/validate-request/",
    [":authority"] = DATADOME_ENDPOINT,
    ["Content-Type"] = "application/x-www-form-urlencoded",
    ["Connection"] = "keep-alive"
  }
  if is_client_id_from_header == true then
    request_header["X-DataDome-X-Set-Cookie"] = "true"
  end
  local headers, datadome_response_body = request_handle:httpCall(
    DATADOME_CLUSTER_NAME,
    request_header,
    datadome_payload_body, DATADOME_API_TIMEOUT
  )

  -- Add HTTP status code of DataDome API to the request headers
  local status = headers[':status']
  request_handle:headers():add("X-DataDome-status" , status)

  -- check that response is from our ApiServer
  if headers['x-datadomeresponse'] ~= status then
    return
  end

  local datadome_request_headers = parse_xdd_header(headers['x-datadome-request-headers'])
  local datadome_response_headers = parse_xdd_header(headers['x-datadome-headers'])

  -- Add enriched headers to the request headers
  for request_header, _ in pairs(datadome_request_headers) do
    request_handle:headers():replace(request_header, headers[request_header])
  end

  if status == "403" or status == "401" or status == "301" or status == "302" then
    -- Remove headers listed by datadome_request_headers and other DataDome headers that are not listed by datadome_response_headers.
    -- This step is mandatory because we use the same request_handle to send a response to the client
    -- and headers coming from the Protection API that are not listed by x-datadome-headers should not be visible from the client side.
    for datadome_request_header, _ in pairs(datadome_request_headers) do
      if not datadome_response_headers[datadome_request_header] then
        table.removekey(headers, datadome_request_header)
      end
    end

    for _, header_to_remove in ipairs(DATADOME_HEADERS_TO_REMOVE) do
      if headers[header_to_remove] then
        table.removekey(headers, header_to_remove)
      end
    end

    request_handle:respond(headers, datadome_response_body)
  end

  if status == "200" then
    -- update the request
    local dynamicMetadata = request_handle:streamInfo():dynamicMetadata()
    for response_header, _ in pairs(datadome_response_headers) do
      dynamicMetadata:set(DATADOME_TENANT_NAME .. 'datadome-response-headers', response_header, headers[response_header])
    end
    -- store cache-control header
    local cacheControlValue = request_handle:headers():get('cache-control')
    if cacheControlValue then
      dynamicMetadata:set(DATADOME_TENANT_NAME .. 'cache_metadata', 'cache-control', cacheControlValue)
    end
  end
end

function envoy_on_response(response_handle)
  if DATADOME_ENABLE_UNPROTECTED_CACHED_RESPONSE == true and is_cacheable_response(response_handle) then
    return
  end

  local dynamicMetadata = response_handle:streamInfo():dynamicMetadata()
  local datadomeResponseHeaders = dynamicMetadata:get(DATADOME_TENANT_NAME .. 'datadome-response-headers') or {}
  for key, value in pairs(datadomeResponseHeaders) do
    if key == "set-cookie" then
      response_handle:headers():add(key, value)
    else
      response_handle:headers():replace(key, value)
    end
  end
end

-- Headers Truncation
headersLength = {
  ['SecCHUAMobile']           = 8,
  ['SecCHDeviceMemory']       = 8,
  ['SecFetchUser']            = 8,
  ['SecCHUAArch']             = 16,
  ['SecCHUAPlatform']         = 32,
  ['SecFetchDest']            = 32,
  ['SecFetchMode']            = 32,
  ['SecFetchSite']            = 64,
  ['ContentType']             = 64,
  ['SecCHUA']                 = 128,
  ['SecCHUAModel']            = 128,
  ['AcceptCharset']           = 128,
  ['AcceptEncoding']          = 128,
  ['CacheControl']            = 128,
  ['ClientID']                = 128,
  ['Connection']              = 128,
  ['Pragma']                  = 128,
  ['X-Requested-With']        = 128,
  ['From']                    = 128,
  ['TrueClientIP']            = 128,
  ['X-Real-IP']               = 128,
  ['AcceptLanguage']          = 256,
  ['SecCHUAFullVersionList']  = 256,
  ['Via']                     = 256,
  ['XForwardedForIP']         = -512,
  ['Accept']                  = 512,
  ['HeadersList']             = 512,
  ['Host']                    = 512,
  ['Origin']                  = 512,
  ['ServerHostname']          = 512,
  ['ServerName']              = 512,
  ['UserAgent']               = 768,
  ['Referer']                 = 1024,
  ['Request']                 = 2048
}
-- Truncate Header methods
function truncateHeaders(headers)
  for k,v in pairs(headers) do
    if headersLength[k] ~= nil then
      if headersLength[k] > 0 then
        headers[k] = string.sub(v, 1, headersLength[k])
      else  -- backward truncation - String remains untouched if length is 0
        headers[k] = string.sub(v, headersLength[k])
      end
    end
  end
  return headers
end

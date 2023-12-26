local DATADOME_API_KEY = options['API_KEY']

local DATADOME_API_TIMEOUT = options['API_TIMEOUT'] or 100

local DATADOME_URL_PATTERNS = options['URL_PATTERNS'] or {}

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

local DATADOME_MODULE_VERSION="1.3.0"

local DATADOME_REQUEST_PORT=0

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

local function getClientIP(request_handle)
  -- we can't get IP address here otherwise when X-Forwarded-For
  ip = string.gsub(request_handle:headers():get("x-forwarded-for") or "", ",.*", "")
  return ip
end

local function getCurrentMicroTime()
  -- we need time up to microseccconds, but at lua we can do up to seconds :( round it
  return tostring(os.time()) .. "000000"
end

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
  local clientId = nil
  if len > 0 then
    for k, v in string.gmatch(cookie, "([^;= ]+)=([^;$]+)") do
      if k == "datadome" then
        clientId = v
        break
      end
    end
  end
  return clientId, len
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

-- this returns whether the response can be cached
-- according to its cache-control header value
local function is_cacheable_response(response_handle)
	local headers = response_handle:headers()

	local cacheControlValue = headers:get("cache-control")

	if not cacheControlValue then
		return false
	end

	-- gmatch will split the string in order to extract each directive part
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

  -- check if we need validation for this domain
  local authority = headers:get(":authority")

  local matched = false

  for _, pattern in pairs(DATADOME_URL_PATTERNS) do
    if string.match(authority, pattern) then
      matched = true
      break
    end
  end

  if not matched then
    return
  end

  -- check if we want to validate this specific URI
  local pathWithQuery = headers:get(":path")
  local path = string.gsub(pathWithQuery, "?.*", "")

  for _, pattern in pairs(DATADOME_URI_PATTERNS_EXCLUSION) do
    if string.match(path, pattern) then
      return
    end
  end

  local matched = next(DATADOME_URI_PATTERNS) == nil

  for _, pattern in pairs(DATADOME_URI_PATTERNS) do
    if string.match(path, pattern) then
      matched = true
      break
    end
  end

  if not matched then
    return
  end

  local clientIP = headers:get("x-envoy-external-address") or ""
  local clientId, cookieLen = getClientIdAndCookiesLength(request_handle)
  local body = stringify(
    truncateHeaders({
      ["Key"]                    = DATADOME_API_KEY,
      ["RequestModuleName"]      = DATADOME_MODULE_NAME,
      ["ModuleVersion"]          = DATADOME_MODULE_VERSION,
      ["ServerName"]             = hostname,
      ["IP"]                     = getClientIP(request_handle),
      ["Port"]                   = DATADOME_REQUEST_PORT,
      ["TimeRequest"]            = getCurrentMicroTime(),
      ["Protocol"]               = headers:get("x-forwarded-proto"),
      ["Method"]                 = headers:get(":method"),
      ["ServerHostname"]         = headers:get("host"),
      ["Request"]                = pathWithQuery,
      ["HeadersList"]            = getHeadersList(request_handle),
      ["Host"]                   = headers:get("host"),
      ["UserAgent"]              = headers:get("User-Agent"),
      ["Referer"]                = headers:get("referer"),
      ["Accept"]                 = headers:get("accept"),
      ["AcceptEncoding"]         = headers:get("accept-encoding"),
      ["AcceptLanguage"]         = headers:get("accept-language"),
      ["AcceptCharset"]          = headers:get("accept-charset"),
      ["Origin"]                 = headers:get("origin"),
      ["XForwardedForIP"]        = headers:get("x-forwarded-for"),
      ["X-Requested-With"]       = headers:get("x-requested-with"),
      ["Connection"]             = headers:get("connection"),
      ["Pragma"]                 = headers:get("pragma"),
      ["CacheControl"]           = headers:get("cache-control"),
      ["CookiesLen"]             = tostring(cookieLen),
      ["AuthorizationLen"]       = tostring(getAuthorizationLen(request_handle)),
      ["PostParamLen"]           = headers:get("content-length"),
      ["ClientID"]               = clientId,
      ["SecCHUA"]                = headers:get("Sec-CH-UA"),
      ["SecCHUAMobile"]          = headers:get("Sec-CH-UA-Mobile"),
      ["SecCHUAPlatform"]        = headers:get("Sec-CH-UA-Platform"),
      ["SecCHUAArch"]            = headers:get("Sec-CH-UA-Arch"),
      ["SecCHUAFullVersionList"] = headers:get("Sec-CH-UA-Full-Version-List"),
      ["SecCHUAModel"]           = headers:get("Sec-CH-UA-Model"),
      ["SecCHDeviceMemory"]      = headers:get("Sec-CH-Device-Memory"),
      ["SecFetchDest"]           = headers:get("Sec-Fetch-Dest"),
      ["SecFetchMode"]           = headers:get("Sec-Fetch-Mode"),
      ["SecFetchSite"]           = headers:get("Sec-Fetch-Site"),
      ["SecFetchUser"]           = headers:get("Sec-Fetch-User"),
    })
  )

  local headers, body = request_handle:httpCall(
    "outbound|443||{{ .Values.datadome.api_url }}",
    {
      [":method"] = "POST",
      [":path"] = "/validate-request/",
      [":authority"] = "{{ .Values.datadome.api_url }}",
      ["user-agent"] = "DataDome",
      ["Content-Type"] = "application/x-www-form-urlencoded"
    },
    body,
    DATADOME_API_TIMEOUT
  )

  local status = headers[':status']
  -- For logging purposes
  request_handle:headers():add("X-DataDome-status" , status)

  -- check that response is from our ApiServer
  if not headers['x-datadomeresponse'] == status then
    return
  end

  local request_headers = parse_xdd_header(headers['x-datadome-request-headers'])
  local response_headers = parse_xdd_header(headers['x-datadome-headers'])

  -- Unconditionally update the request headers for logging purposes
  for request_header, _ in pairs(request_headers) do
    request_handle:headers():replace(request_header, headers[request_header])
  end

  if status == "403" or status == "401" or status == "301" or status == "302" then
    -- cleanup request headers
    for request_header, _ in pairs(request_headers) do
      if not response_headers[request_headers] then
        table.removekey(headers, request_header)
      end
    end
    request_handle:respond(headers, body)
  end

  if status == "200" then
    -- update the request
    for request_header, _ in pairs(request_headers) do
      request_handle:headers():replace(request_header, headers[request_header])
    end
    local dynamicMetadata = request_handle:streamInfo():dynamicMetadata()
    for response_header, _ in pairs(response_headers) do
      dynamicMetadata:set("datadome-response-headers", response_header, headers[response_header])
    end
  end
end

function envoy_on_response(response_handle)
  -- if response is cacheable we don't want to add any datadome cookie
	-- as they would prevent the response to be considered cacheable by CDN
	-- downstream
	-- @see https://cloud.google.com/cdn/docs/caching#non-cacheable_content
	if is_cacheable_response(response_handle) then
		return
	end

  local dynamicMetadata = response_handle:streamInfo():dynamicMetadata()
  local datadomeResponseHeaders = dynamicMetadata:get("datadome-response-headers") or {}
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

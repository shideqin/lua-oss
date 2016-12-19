local http = require 'socket.http'
local ltn12 = require 'ltn12'
local crypto = require 'crypto'
local mimetypes = require 'mimetypes'

local oss = {
    bucket = "",
    access_id = "",
    access_key = ""
}

local conn = {}

function oss:Connect(options)
    self.bucket = options["bucket"]
    self.access_id = options["access_id"]
    self.access_key = options["access_key"]
    self.host = "http://"..self.bucket.."."..options["endpoint"]..".aliyuncs.com"
    return setmetatable(conn,{
        __index = oss
    })
end

function conn:Put(bytes,object)
    local url = self.host.."/"..object
    local method = "PUT"
    local mime = mimetypes.guess(object)
    local result,code,headers,status = http.request{
        url = url,
        method = method,
        headers = {
            ["Content-Length"] = #bytes,
            ["Content-Md5"] = self:hex_to_base64(ngx.md5(bytes)),
            ["Content-Type"] = mime,
            ["Date"] = ngx.http_time(ngx.now()),
            ["Authorization"] = self:sign(method,object,mime,bytes)
        },
        source = ltn12.source.string(bytes)
    }
    return {result=result,code=code,headers=headers,status=status},url
end

function conn:Get(object)
    local url = self.host.."/"..object
    local method = "GET"
    local mime = "application/x-www-form-urlencoded"
    local body = {}
    local result,code,headers,status = http.request{
        url = url,
        method = method,
        headers = {
            ["Content-Type"] = mime,
            ["Date"] = ngx.http_time(ngx.now()),
            ["Authorization"] = self:sign(method,object,mime)
        },
        sink = ltn12.sink.table(body)
    }
    return {result=result,code=code,headers=headers,status=status},table.concat(body)
end

function conn:InitUpload(object,options)
    local url = self.host.."/"..object.."?uploads"
    local method = "POST"
    local mime = mimetypes.guess(object)
    local body = {}
    local disposition = ""
    if options and options["disposition"] then
        disposition = options["disposition"]
    end
    local result,code,headers,status = http.request{
        url = url,
        method = method,
        headers = {
            ["Content-Type"] = mime,
            ["Date"] = ngx.http_time(ngx.now()),
            ["Authorization"] = self:sign(method.."\n",object.."?uploads",mime),
            ["Content-Disposition"] = "attachment; filename=\""..disposition.."\""
        },
        sink = ltn12.sink.table(body)
    }
    return {result=result,code=code,headers=headers,status=status},table.concat(body)
end

function conn:UploadPart(bytes,object,partNum,uploadId)
    local url = self.host.."/"..object.."?partNumber="..partNum.."&uploadId="..uploadId
    local method = "PUT"
    local mime = mimetypes.guess(object)
    local result,code,headers,status = http.request{
        url = url,
        method = method,
        headers = {
            ["Content-Type"] = mime,
            ["Date"] = ngx.http_time(ngx.now()),
            ["Authorization"] = self:sign(method.."\n",object.."?partNumber="..partNum.."&uploadId="..uploadId,mime),
            ["Content-Length"] = #bytes
        },
        source = ltn12.source.string(bytes)
    }
    return {result=result,code=code,headers=headers,status=status}
end

function conn:AbortUpload(object,uploadId)
    local url = self.host.."/"..object.."?uploadId="..uploadId
    local method = "DELETE"
    local result,code,headers,status = http.request{
        url = url,
        method = method,
        headers = {
            ["Date"] = ngx.http_time(ngx.now()),
            ["Authorization"] = self:sign(method.."\n\n",object.."?".."uploadId="..uploadId)
        }
    }
    return {result=result,code=code,headers=headers,status=status}
end

function conn:CompleteUpload(bytes,object,uploadId)
    local url = self.host.."/"..object.."?uploadId="..uploadId
    local method = "POST"
    local mime = mimetypes.guess(object)
    local body = {}
    local result,code,headers,status = http.request{
        url = url,
        method = method,
        headers = {
            ["Content-Length"] = #bytes,
            ["Content-Md5"] = self:hex_to_base64(ngx.md5(bytes)),
            ["Content-Type"] = mime,
            ["Date"] = ngx.http_time(ngx.now()),
            ["Authorization"] = self:sign(method,object.."?uploadId="..uploadId,mime,bytes),
            
        },
        source = ltn12.source.string(bytes),
        sink = ltn12.sink.table(body)
    }
    return {result=result,code=code,headers=headers,status=status},table.concat(body)
end

function conn:sign(method,object,mime,bytes)
    local LF = "\n"
    if method == "GET" then
        method = method..LF
    end
    local sign = method..LF
    if bytes then
        sign = sign..self:hex_to_base64(ngx.md5(bytes))..LF
    end
    if mime then
        sign = sign..mime..LF
    end
    sign = sign..ngx.http_time(ngx.now())..LF
    sign = sign.."/"..self.bucket.."/"..object
    return "OSS "..self.access_id..":"..ngx.encode_base64(crypto.hmac.digest("sha1",sign,self.access_key,true))
end

function conn:hex_to_base64(str)
    local result = ''
    for i = 1, #str, 2 do
        local tmp = string.sub(str, i, i+1)
        result = result..string.char(tonumber(tmp,16))
    end
    return ngx.encode_base64(result)
end

return oss

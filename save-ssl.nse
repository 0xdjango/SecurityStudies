local datetime = require "datetime"
local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local unicode = require "unicode"
local have_openssl, openssl = pcall(require, "openssl")

description = [[
Retrieves a server's SSL certificate. The amount of information printed
about the certificate depends on the verbosity level. With no extra
verbosity, the script prints the validity period and the commonName,
organizationName, stateOrProvinceName, and countryName of the subject.
]]
author = "David Fifield"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "default", "safe", "discovery" }
dependencies = {"https-redirect"}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end


local function output_tab(cert)
    return {cert.pem}
  end
---
--Writes string to file
--Taken from: hostmap.nse
-- @param filename Filename to write
-- @param contents Content of file
-- @return True if file was written successfully
local function write_file (filename, contents)
  local f, err = io.open(filename, "w");
  if not f then
    return f, err;
  end
  f:write(contents);
  f:close();
  return true;
end


action = function(host, port)
  host.targetname = tls.servername(host)
  local status, cert = sslcert.getCertificate(host, port)
  if ( not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end
  local service_prefix = port.service
    local fname = service_prefix .. "_" .. host.ip .. "_" .. port.number .. ".pem"

  return write_file(fname,cert.pem)
end

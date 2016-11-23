local stun = require "stun"
local socket = require "socket"
local pretty = require "pl.pretty"

local usock = socket.udp()
--local stun_server = assert(arg[1])

for stun_server in string.gmatch([[
stun.ekiga.net
stun.sipnet.ru
stun.ideasip.com
stun.1und1.de
stun.bluesip.net
stun.callwithus.com
stun.counterpath.net
stun.e-fon.ch
stun.endigovoip.com
stun.gmx.net
stun.ideasip.com
stun.noc.ams-ix.net
stun.phoneserve.com
stun.sipgate.net
stun.voip.aebc.com
stun.voipgate.com
]], "(%S+)") do

	local data, descr = stun.request(usock, stun_server)

	if data then
		local attr = data["XOR-MAPPED-ADDRESS"] or data["MAPPED-ADDRESS"]
		if attr then
			print(string.format("OK. public address received from %s is %s:%d (%s)", stun_server,
					attr.ip, attr.port, attr.descr))
		else
			--[[
			print(string.format("OK. Attributes received from %s are:\n%s", stun_server,
					pretty.write(data)))
			]]
			print(string.format("Server error: Attributes received from %s "
					.."but there are no suitable adresses inside.", stun_server))
		end
	else
		print("Connection error:", descr)
	end
end

usock:close()


local socket = require "socket"

local m = {}

local function strtohex (str)
	local t = {}
	for i = 1, #str do
		table.insert(t, string.format("%02X", string.byte(str, i)))
	end
	return table.concat(t, "")
end

local function splitbytetobits (b1)
	local b1_t = {}
	for i = 8, 1, -1 do
		b1_t[i] = b1 % 2
		b1 = math.floor(b1 / 2)
	end
	return b1_t
end

local function joinbitstobyte (b1_t)
	local b1 = 0
	for i = 1, 8 do
		b1 = b1 * 2
		b1 = b1 + b1_t[i]
	end
	return b1
end

local function softbytexor (b1, b2)
	local b1_t = splitbytetobits(b1)
	local b2_t = splitbytetobits(b2)
	local bR_t = {}
	for i = 1, 8 do
		if b1_t[i] == b2_t[i] then
			bR_t[i] = 0
		else
			bR_t[i] = 1
		end
	end
	return joinbitstobyte(bR_t)
end

local function strxor (str1, str2)
	local chars = {}
	for i = 1, #str1 do
		local b1 = string.byte(str1, i)
		local b2 = string.byte(str2, i)
		local bR = softbytexor(b1, b2)
		chars[i] = string.char(bR)
	end
	return table.concat(chars)
end

local function getshort (str, offset)
	return string.byte(str, offset) * 256 + string.byte(str, offset + 1)
end

local function getip (str, offset)

	-- DEBUG
	print("getip() @str length:", #str)
	print("getip() @offset:", offset)

	local ip = string.format("%d.%d.%d.%d",
			string.byte(str, offset + 0),
			string.byte(str, offset + 1),
			string.byte(str, offset + 2),
			string.byte(str, offset + 3)
	)
	return ip
end



print("bits of 3:", table.concat(splitbytetobits(3)))
print("bits of 2:", table.concat(splitbytetobits(2)))
print("bits of 5:", table.concat(splitbytetobits(5)))
print("bits of 7:", table.concat(splitbytetobits(7)))
print("bits of 128:", table.concat(splitbytetobits(128)))
print("bits of 127:", table.concat(splitbytetobits(127)))
print("bits of 255:", table.concat(splitbytetobits(255)))

print("byte from bits of 7:", joinbitstobyte(splitbytetobits(7)))
print("byte from bits of 3:", joinbitstobyte(splitbytetobits(3)))
print("byte from bits of 255:", joinbitstobyte(splitbytetobits(255)))
print("xor(7, 2):", softbytexor(7, 2))
print("xor(7, 1):", softbytexor(7, 1))
print("xor(255, 128):", softbytexor(255, 128))



function m.request (usock, stun_addr, stun_port)
	
	stun_port = tonumber(stun_port or 3478)
	assert(stun_port)
	print("stun_server:", stun_addr, socket.dns.toip(stun_addr))
	print("stun_port:", stun_port)
	assert(usock)

	--local usock = socket.udp()

	-- Generate ID
	math.randomseed(os.time() % 1373)
	math.random()
	local id_t = {}
	for i = 1, 12 do
		table.insert(id_t, string.char(math.random(0, 255)))
	end
	local id = table.concat(id_t, "")
	print("id:", strtohex(id))

	-- Assemble magick
	local magick = string.char(0x21, 0x12, 0xA4, 0x42)
	print("magick:", strtohex(magick))

	-- Build header
	local hdr = {}
	table.insert(hdr, string.char(0x00, 0x01)) -- message type
	table.insert(hdr, string.char(0x00, 0x00)) -- data length
	table.insert(hdr, magick) -- magick
	table.insert(hdr, id) -- id

	stun_req = table.concat(hdr, "")
	local stun_header_size = #stun_req

	print("STUN request:", strtohex(stun_req))

	local response, r_ip, r_port, r_magick, r_id

	for i = 1, 5 do

		print("try #"..i)

		local stun_ip = socket.dns.toip(stun_addr)
		usock:sendto(stun_req, stun_ip, stun_port)

		usock:settimeout(0.5)

		response, r_ip, r_port = usock:receivefrom()

		if response then
			r_magick = string.sub(response, 5, 8)
			r_id = string.sub(response, 9, 9 + 11)
	
			if r_magick == magick
			and r_id == id
			then
				break
			end
		else
			print("No response")
		end

		socket.sleep(0.5)
	end



	if response then

		--[[
		local fd = assert(io.open("response_dgram.bin", "wb"))
		fd:write(response)
		fd:close()
		usock:close()
		return response
		]]
		
		local header = string.sub(response, 1, stun_header_size)
		local data_length = getshort(header, 3)
		local data = string.sub(response, stun_header_size + 1, stun_header_size + data_length)
		print("data length from header:", data_length)
		print("response data length:", #data)

		-- Get attributes, parse them and store them in array
		local offset = 1
		local attributes = {}
		while offset < data_length do

			local attr = {}
			attr.offset = offset
			attr.type = getshort(data, offset)
			attr.length = getshort(data, offset + 2)
			attr.body = string.sub(data, offset + 4, offset + 4 + attr.length)
			attr.data = attr.body

			--[[ INVESTIGATION
			print(string.format("attr.offset: %d", attr.offset))
			print(string.format("attr.type: %04X", attr.type))
			print(string.format("attr.length: %d", attr.length))
			print(string.format("attr.body: %s", strtohex(attr.body)))
			print()
			]]

			-- attribute type is "MAPPED-ADDRESS"
			if attr.type == 1 then
				attr.descr = "MAPPED-ADDRESS"
				attr.ip_version = string.byte(attr.data, 2) * 2 + 2
				attr.port = getshort(attr.data, 3)
				attr.ip = getip(attr.data, 5)

				attr.body = nil
				attr.data = nil
			end

			-- attribute type is "SOURCE-ADDRESS"
			if attr.type == 4 then
				attr.descr = "SOURCE-ADDRESS"
				attr.ip_version = string.byte(attr.data, 2) * 2 + 2
				attr.port = getshort(attr.data, 3)
				attr.ip = getip(attr.data, 5)

				attr.body = nil
				attr.data = nil
			end

			-- attribute type is "CHANGED-ADDRESS"
			if attr.type == 5 then
				attr.descr = "CHANGED-ADDRESS"
				attr.ip_version = string.byte(attr.data, 2) * 2 + 2
				attr.port = getshort(attr.data, 3)
				attr.ip = getip(attr.data, 5)

				attr.body = nil
				attr.data = nil
			end

			-- attribute type is "XOR-MAPPED-ADDRESS"
			if attr.type == 0x8020 then
				attr.descr = "XOR-MAPPED-ADDRESS"
				attr.ip_version = string.byte(attr.data, 2) * 2 + 2
				local xor_port_string = string.sub(attr.data, 3, 4)
				local xor_ip_string = string.sub(attr.data, 5, 8)
				print("xor_ip_string: "..strtohex(xor_ip_string))
				local normal_port_string = strxor(xor_port_string, magick)
				local normal_ip_string = strxor(xor_ip_string, magick)
				attr.port = getshort(normal_port_string, 1)
				attr.ip = getip(normal_ip_string, 1)

				attr.body = nil
				attr.data = nil
			end

			table.insert(attributes, attr)
			offset = offset + 4 + attr.length
		end

		-- DEBUG
		local pretty = require "pl.pretty"
		print(pretty.write(attributes))

	else
		return nil, "response timeout"
	end
end

return m


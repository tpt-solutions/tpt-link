-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Copyright (c) 2026 TPT Solutions

-- Wireshark dissector for the tpt-link frame format, version 1 (docs/wire-format.md).
--
-- Install: copy this file into the Wireshark personal plugin folder
-- (Help > About > Folders > Personal Lua Plugins), or open it from the Lua console.
--
-- It dissects UDP payloads on the ports in PORTS below. For a serial or CAN capture,
-- call the dissector yourself on the reassembled bytes, or use a raw-byte export.
--
-- The CRC is checked with plain arithmetic, so the script runs on any Lua build
-- (Wireshark's LuaJIT included) without the bit library.

local PORTS = { 7100, 7200 } -- change to the UDP ports your link uses

local CRC_POLY = 0xEDB88320
local MAX_PAYLOAD = 1024
local HEADER_LEN = 7
local TRAILER_LEN = 4

local tpt_link = Proto("tpt_link", "TPT Link frame v1")

local f_version = ProtoField.uint8("tpt_link.version", "Version", base.DEC)
local f_seq = ProtoField.uint32("tpt_link.seq", "Sequence", base.DEC)
local f_length = ProtoField.uint16("tpt_link.length", "Payload length", base.DEC)
local f_payload = ProtoField.bytes("tpt_link.payload", "Payload")
local f_crc = ProtoField.uint32("tpt_link.crc", "CRC-32 (carried)", base.HEX)
local f_crc_ok = ProtoField.string("tpt_link.crc_status", "CRC status")

tpt_link.fields = { f_version, f_seq, f_length, f_payload, f_crc, f_crc_ok }

-- XOR of two unsigned 32-bit values, built from arithmetic only.
local function xor32(a, b)
    local result, power = 0, 1
    for _ = 1, 32 do
        local x, y = a % 2, b % 2
        if x ~= y then
            result = result + power
        end
        a = (a - x) / 2
        b = (b - y) / 2
        power = power * 2
    end
    return result
end

-- CRC-32 (IEEE 802.3, reflected), the same as zlib's crc32 over `len` bytes of tvb.
local function crc32(tvb, offset, len)
    local crc = 0xFFFFFFFF
    for i = offset, offset + len - 1 do
        crc = xor32(crc, tvb(i, 1):uint())
        for _ = 1, 8 do
            local low = crc % 2
            crc = (crc - low) / 2
            if low == 1 then
                crc = xor32(crc, CRC_POLY)
            end
        end
    end
    return xor32(crc, 0xFFFFFFFF)
end

function tpt_link.dissector(tvb, pinfo, tree)
    local total = tvb:len()
    if total < HEADER_LEN + TRAILER_LEN then
        return 0
    end
    local version = tvb(0, 1):uint()
    if version ~= 1 then
        return 0
    end
    local length = tvb(5, 2):le_uint()
    if length > MAX_PAYLOAD then
        return 0
    end
    local frame_len = HEADER_LEN + length + TRAILER_LEN
    if total < frame_len then
        return 0
    end

    pinfo.cols.protocol = "TPT-LINK"
    pinfo.cols.info = string.format("seq=%d len=%d", tvb(1, 4):le_uint(), length)
    local subtree = tree:add(tpt_link, tvb(0, frame_len), "TPT Link frame")

    subtree:add(f_version, tvb(0, 1))
    subtree:add_le(f_seq, tvb(1, 4))
    subtree:add_le(f_length, tvb(5, 2))
    if length > 0 then
        subtree:add(f_payload, tvb(HEADER_LEN, length))
    end

    local crc_offset = HEADER_LEN + length
    local carried = tvb(crc_offset, TRAILER_LEN):le_uint()
    local computed = crc32(tvb, 0, crc_offset)
    subtree:add_le(f_crc, tvb(crc_offset, TRAILER_LEN))
    if carried == computed then
        subtree:add(f_crc_ok, "ok"):set_generated()
    else
        local status = subtree:add(f_crc_ok, string.format("BAD (computed 0x%08X)", computed))
        status:set_generated()
        status:add_expert_info(PI_CHECKSUM, PI_WARN, "CRC mismatch: frame is damaged")
        pinfo.cols.info = "BAD CRC " .. pinfo.cols.info
    end
    return frame_len
end

local udp_port = DissectorTable.get("udp.port")
for _, port in ipairs(PORTS) do
    udp_port:add(port, tpt_link)
end

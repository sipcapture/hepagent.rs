function capture_plan(packet)
    print('STARTED FUN, packet size ' .. packet:size())

    -- here we can check source/destination IP/port, message size
    -- if packet:size() < 100 then
    --     return DROP
    -- end

    -- print('LARGE ENOUGH!')

    -- Do parsing
    if sip:parse(packet) then
        print('SIP PARSED')
    --     -- Many profiles could be defined in transport_hep.xml
    --     if not hep:send("hepsocket") then
    --         clog("ERROR", "Error sending HEP!!!!")
    --     end

    --     if sip:has_sdp() then
    --         -- Activate it for RTCP checks
    --         if not rtcp:check_ipport() then
    --             clog("ERROR", "ALREADY EXIST")
    --         end
    --     end

        -- Duplicate all INVITEs to JSON transport
        if sip:is_method("INVITE") then
            -- Many profiles could be defined in transport_json.xml
            if not json:send("jsonsocket") then
                clog("ERROR", "Error sending JSON!!!")
            end
        end
    end

    return FORWARD
end

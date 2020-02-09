function capture_plan( packet )
    -- here we can check source/destination IP/port, message size
    if #packet < 10 then
        return DROP
    end

    -- attempt TLS parsing
    if tls:parse() then
        -- attempt SIP parsing
        if sip:parse(packet) then
            -- Send using a profile defined in transport_hep.xml
            if not hep:send("hepsocket") then
                clog("ERROR", "Error sending HEP!!!!")
            end

            -- attempt SDP parsing
            if sip:has_sdp() then
                -- Activate it for RTCP checks
                if not rtcp:check_ipport() then
                    clog("ERROR", "Duplicate SDP Session!")
                end
            end
        else
            clog("ERROR", "Error parsing SIP!!!!")
        end
    else
        clog("ERROR", "Error parsing TLS!!!!")
    end

    return DROP
end

function capture_plan( packet )
    -- here we can check source/destination IP/port, message size
    if #packet < 10 then
        return DROP
    end

    -- check if pkt is rtcp-xr
    if is_rtcpxr() then
        -- if yes, parse the field and make a json output
        if parse_rtcpxr_to_json() then
            if not send_hep("hepsocket") then
                clog("ERROR", "Error sending !!!!")
            end
        else
            clog("ERROR", "couldn't parse RTCP-XR to json")
        end
    else
        clog("ERROR", "This is not RTCP-XR")
    end

    -- Do parsing
    if parse_full_sip() then
        -- check if our method is PUBLISH
        if sip_is_method() and sip_check("method","PUBLISH") then
            -- Currently we send reply automaticaly
            -- send_rtcpxr_reply("200", "OK");

            -- Can be defined many profiles in transport_hep.xml
            if not send_hep_proto("hepsocket", "99") then
                clog("ERROR", "Error sending HEP!!!!")
            end
        else
            send_reply("503", "Server internal error")
        end
    end

    return DROP
end

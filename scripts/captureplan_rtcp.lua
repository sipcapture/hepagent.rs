function capture_plan( packet )
    -- here we can check source/destination IP/port, message size
    if #packet < 30 then
        return DROP
    end

    -- Check for correct version
    if not is_rtcp() then
        clog("ERROR", "This is not RTCP")
        return DROP
    end

    -- Only for redis!
    if not is_rtcp_exist() then
        clog("ERROR", "Couldnot find this call")
        return DROP
    end

    -- Convert to JSON if needed.
    if not parse_rtcp_to_json() then
        clog("ERROR", "couldn't parse RTCP to json")
        return DROP
    end

    -- Can be defined many profiles in transport_hep.xml
    if not send_hep("hepsocket") then
        clog("ERROR", "Error sending HEP!!!!")
    end

    return DROP
end

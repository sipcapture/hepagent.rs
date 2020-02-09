function capture_plan( packet )
    -- here we can check source/destination IP/port, message size
    if #packet < 100 then
        return DROP
    end

    -- check if pkt is diameter
    if not is_diameter() then
        clog("ERROR", "This is not DIAMETER")
        return DROP
    end

    -- if yes, parse the field and make a json output
    if not parse_diameter_to_json() then
        clog("ERROR", "couldn't parse DIAMETER to json")
        return DROP
    end

    if not send_hep("hepsocket") then
        clog("ERROR", "Error sending !!!!")
    end

    return DROP
end

function capture_plan( packet )
    -- here we can check source/destination IP/port, message size
    if #packet < 100 then
        return DROP
    end

    -- Do parsing
    if not tzsp_payload_extract() then
        return DROP
    end

    -- check if the message is sip
    if parse_sip() then
        if not send_hep("hepsocket") then
            clog("ERROR", "Error sending HEP!!!!")
        end
    end

    return DROP
end

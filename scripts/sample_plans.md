* we got a sip message, parse it,
    * check if it has SDP - parse sdp, 
        * check if method is OPTIONS - drop it, 
    * check if the source_ip is 10.0.0.1 - drop it,
    * if SDP exists - make a dialog for call,
    * after send a message as a HEP packet to Homer
* if you receive RTCP packet -> 
    * check if IP exists in the hash map (SDP PARSER extract all media IP and port and make two HASH records IP:PORT = callid and callid = IP:PORT)
    * if IP:PORT exist - parse RTCP to JSON and use callid to send a HEP message with correlation information


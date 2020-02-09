// LuaJIT has wares if you got coin.
//
// TODO
// [ ] Load and store scripts in memory
// [x] Enable LuaJIT (rlua + luajit = could be compiled, but rlua expects lua 5.3, while luajit is 5.1)
// [?] Pass packet buffer to lua script
// [ ] Pass structured packet accessors (i.e. as RTCP or DNS packets) to script
//     [ ] Need to pass a typed object?
// [ ] Pass data back from scripts and make decisions based on that
//     [ ] Implement feedback API
//

use errors::*;
use luajit::{c_int, ffi, LuaObject, State, ThreadStatus};
use pnet::packet::{Packet, PacketSize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Scripting structure holds state of the lua interpreter.
pub struct Scripting {
    pub lua: State,
}

// 1. pass received buffer to lua
// 2. lua function evaluates and probably calls some rust functions
// 3. lua function returns final result - DROP, FORWARD, etc
//
// If the script itself just needs to keep a pointer to pass between functions, blobs of C data are usually pushed as light userdata:
// lua_pushlightuserdata(L, bufptr);
// wrap you C++ byte array in a lightuserdata and provide Lua bindings to let you access it directly. This is the most efficient, but is quite a lot of code.
//
// When passing arrays of bytes to Lua, strings are normally used (strings of arbitrary data can be created using lua_pushlstring):
// lua_pushlstring (L, bufptr, buflen);
// This will create an immutable string in Lua, which can only be modified by creating new strings

impl Scripting {
    pub fn new() -> Self {
        let mut lua = State::new();
        // Open libraries selectively, to provide sandboxing
        lua.open_base();
        lua.open_string();
        lua.open_table();
        lua.open_math();
        // Init some constants
        lua.push(1);
        lua.set_global("DROP");
        lua.push(1);
        lua.set_global("BREAK"); // Synonym for DROP
        lua.push(2);
        lua.set_global("FORWARD");

        // You can bind rust functions to lua as well.  Callbacks receive the Lua state itself as their
        // first parameter, and the arguments given to the function as the second parameter.  The type
        // of the arguments can be anything that is convertible from the parameters given by Lua, in
        // this case, the function expects two string sequences.

        // let msg_check = lua.create_function(|_, (name, param): (String, String)| {
        //     // This function just checks whether two string lists are equal, and in an inefficient way.
        //     // Lua callbacks return `rlua::Result`, an Ok value is a normal return, and an Err return
        //     // turns into a Lua 'error'.  Again, any type that is convertible to lua may be returned.
        //     Ok(name == param)
        // }).unwrap();
        // globals.set("msg_check", msg_check).unwrap();

        lua.load_file(Path::new("scripts/captureplan_sip.lua"))
            .expect("Unable to open plan file");

        let res = lua.pcall(0, 0, 0);
        assert_eq!(res, Ok(()));

        let mut me = Self { lua };

        #[cfg(feature = "sip")]
        ::decoders::sip::register_module(&mut me);

        me
    }

    // @todo EACH thread has it's own copy of Scripting to avoid cross-thread-talk
    // But we need to maintain hashmap across threads with sessions state.

    //@todo: export functions from rust to lua to be callable:
    //capture plan:
    //
    //these should be registerable from each module
    //e.g. DIAMETER module would register diameter-related functions
    //modules can be enabled a) cargo features, b) dynamic libs - @todo

    // * callable functions:
    // TCP:
    //     * parse_tls `tls:parse`
    // SIP:
    //     + msg_check `remove?`
    //     * sip_check `sip:check`
    //     * sip_is_method `sip:is_method`
    //     * parse_sip `sip:parse`
    //     * parse_full_sip `sip:parse_full`
    //     * clog `common:log?`
    //     * sip_has_sdp `sip:has_sdp`
    //     * send_reply `??`
    // RTCP:
    //     * is_rtcp `rtcp:detect`
    //     * is_rtcp_exist
    //     * parse_rtcp_to_json `rtcp:parse_to_json`
    // RTCP-XR:
    //     * is_rtcpxr `rtcpxr:detect`
    //     * parse_rtcpxr_to_json `rtcpxr:parse_to_json`
    // DIAMETER:
    //     * is_diameter `diameter:detect`
    //     * parse_diameter_to_json `diameter:parse_to_json`
    // TZSP:
    //     * tzsp_payload_extract `tzsp:extract_payload`
    // DATABASE_HASH:
    //     * check_rtcp_ipport `rtcp:check_ipport`
    // TRANSPORT_HEP:
    //     * send_hep `hep:send`
    //     * send_hep_proto `hep:send_proto`
    // TRANSPORT_JSON:
    //     * send_json `json:send`

    // TRANSPORT_HEP:
    // static cmd_export_t cmds[] = {
    // {"transport_hep_bind_api",  (cmd_function)bind_usrloc,   1, 0, 0, 0},
    // {"bind_transport_hep",  (cmd_function)bind_transport_hep,  0, 0, 0, 0},
    // { "send_hep", (cmd_function) w_send_hep_api, 1, 0, 0, 0 },
    // { "send_hep", (cmd_function) w_send_hep_api_param, 2, 0, 0, 0 },
    // { "send_hep_proto", (cmd_function) w_send_hep_proto, 2, 0, 0, 0 },

    // DATABASE_HASH:
    // static cmd_export_t cmds[] = {
    //  {"database_hash_bind_api",  (cmd_function)bind_api,   1, 0, 0, 0},
    //  {"check_rtcp_ipport", (cmd_function) w_check_rtcp_ipport, 0, 0, 0, 0 },
    //  {"is_rtcp_exist", (cmd_function) w_is_rtcp_exists, 0, 0, 0, 0 },
    //  {"bind_database_has",  (cmd_function)bind_database_hash,  0, 0, 0, 0},

    // TCP:
    // static cmd_export_t cmds[] =
    //   {"proto_tcp_bind_api", (cmd_function) bind_api, 1, 0, 0, 0},
    //   {"parse_tls",          (cmd_function) w_parse_tls, 0, 0, 0, 0 },
    //   {"bind_protocol_tcp",  (cmd_function) bind_protocol_tcp, 0, 0, 0, 0},

    // SS7:
    // "parse_isup"

    // SIP:
    // static cmd_export_t cmds[] =
    //         {"protocol_sip_bind_api",  (cmd_function)bind_api,   1, 0, 0, 0},
    //       +  {"msg_check", (cmd_function) w_proto_check_size, 2, 0, 0, 0 },
    //         {"sip_check", (cmd_function) w_sip_check, 2, 0, 0, 0 },
    //         {"sip_is_method", (cmd_function) w_sip_is_method, 0, 0, 0, 0 },
    //         {"light_parse_sip", (cmd_function) w_light_parse_sip, 0, 0, 0, 0 },
    //         {"parse_sip", (cmd_function) w_parse_sip, 0, 0, 0, 0 },
    //         {"parse_full_sip", (cmd_function) w_parse_full_sip, 0, 0, 0, 0 },
    //         {"clog", (cmd_function) w_clog, 2, 0, 0, 0 },
    //         /* ================================ */
    //         {"sip_has_sdp", (cmd_function) w_sip_has_sdp, 0, 0, 0, 0 },
    //         {"is_flag_set", (cmd_function) w_is_flag_set, 2, 0, 0, 0 },
    //         {"send_reply", (cmd_function) w_send_reply_p, 2, 0, 0, 0 },
    //         {"send_reply", (cmd_function) w_send_reply, 0, 0, 0, 0 },
    //         {"send_rtcpxr_reply", (cmd_function) w_send_reply_p, 2, 0, 0, 0 },
    //         {"send_rtcpxr_reply", (cmd_function) w_send_reply, 0, 0, 0, 0 },
    // RTCP-XR:
    // static cmd_export_t cmds[] =
    //   {"protocol_rtcpxr_bind_api", (cmd_function) bind_api, 1, 0, 0, 0 },
    //   {"parse_rtcpxr_to_json", (cmd_function) w_parse_rtcpxr_to_json, 0, 0, 0, 0 },
    //   {"is_rtcpxr", (cmd_function) w_is_rtcpxr, 0, 0, 0, 0 },

    // RTCP:

    // static cmd_export_t cmds[] =
    //   {"protocol_rtcp_bind_api",  (cmd_function)bind_api,   1, 0, 0, 0},
    //   {"parse_rtcp_to_json", (cmd_function) w_parse_rtcp_to_json, 0, 0, 0, 0 },
    //   {"is_rtcp", (cmd_function) w_is_rtcp, 0, 0, 0, 0 },
    //   {"is_rtcp_or_rtp", (cmd_function) w_is_rtcp_or_rtp, 0, 0, 0, 0 },
    //   {"set_rtcp_flag", (cmd_function) w_set_rtcp_flag, 0, 0, 0, 0 },

    // EPAN:
    //         .name       = "parse_epan", -- not implemented?

    // DIAMETER:

    // static cmd_export_t cmds[] = {
    //   {"protocol_diameter_bind_api", (cmd_function) bind_api, 1, 0, 0, 0 },
    //   {"parse_diameter_to_json", (cmd_function) w_parse_diameter_to_json, 0, 0, 0, 0 }, {"is_diameter", (cmd_function) w_is_diameter, 0, 0, 0, 0 },

    // 1. list globals, figure out namespacing
    // 2. made modules register functions under module name, e.g. sip:parse(packet)
    // 3. packet here may be regular userdata that is extracted on the rust side again
    // 4. add codegen macros to extract userdata?
    // 5. maybe run over the #[packet] annotation again?

    /// Run loaded capture plan over the given packet
    pub fn run(&mut self, p: &PacketSize) -> Result<(), Error> {
        self.lua.get_global("capture_plan"); // nil?
        self.lua.push(PacketLua(p));
        let res = self.lua.pcall(1, 1, 0);
        info!("Script returned: {:?}", res);
        assert_eq!(res, Ok(()));
        // @todo need to balance the stack here ??
        // if let Some(retval) = self.lua.to_int(0) {
        //     info!("Script return value: {}", retval);
        // }
        Ok(())
    }
}

/// @todo These wrappers must be generated for all #[packet] structs
pub struct PacketLua<'a>(&'a PacketSize);

impl<'a> PacketLua<'a> {
    pub fn payload(&self) -> &'a [u8] {
        self.0.payload()
    }

    // fn data(&mut self, state: &mut State) -> c_int {
    //     // @todo Push immutable string repr of the packet onto Lua stack
    //     0
    // }

    fn size(&mut self, state: &mut State) -> c_int {
        let size = self.0.packet_size() + self.0.payload().len();
        state.push(size as u64);
        1
    }
}

// Impl the same for decoders?
// Need to put them in globals actually
// i.e. register metatable "sip" with methods etc

impl<'a> LuaObject for PacketLua<'a> {
    fn name() -> *const i8 {
        c_str!("Packet")
    }

    fn lua_fns() -> Vec<ffi::luaL_Reg> {
        vec![
            // lua_method!("data", PacketLua, PacketLua::data),
            lua_method!("size", PacketLua, PacketLua::size),
            lua_method_null!(),
        ]
    }
}

use lua::{PacketLua, Scripting};
use luajit::{c_int, ffi, LuaObject, State};
use parsip;

pub struct SipDecoder;

impl SipDecoder {
    fn parse(&mut self, state: &mut State) -> c_int {
        let packet = unsafe {
            &mut *state
                .check_userdata::<PacketLua>(2)
                .expect("sip:parse received something that is not packet")
        };

        trace!(
            "Packet payload when received from Lua: {:?}",
            packet.payload()
        );

        let mut headers = [parsip::EMPTY_HEADER; 256]; // @todo use pool for storage?
        let result = parsip::Request::new(&mut headers).parse(packet.payload());
        if let parsip::IResult::Done(remain, unparsed) = result {
            info!("SIP parsed: {:?}", remain); // @todo push sip object here?
            info!("SIP parsed: {:?}", unparsed); // @todo push sip object here?
            state.push(true);
        } else {
            info!("NOT SIP"); // @todo otherwise push nil
            state.push(false);
        }

        1
    }
}

impl LuaObject for SipDecoder {
    fn name() -> *const i8 {
        c_str!("SIP")
    }

    fn lua_fns() -> Vec<ffi::luaL_Reg> {
        vec![
            lua_method!("parse", SipDecoder, SipDecoder::parse),
            lua_method_null!(),
        ]
    }
}

// register parse func
pub fn register_module(script: &mut Scripting) {
    info!("Registering SIP module");
    script.lua.push(SipDecoder {});
    script.lua.set_global("sip");
}

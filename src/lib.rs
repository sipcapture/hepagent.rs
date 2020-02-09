//=======================================================================================
// LuaJIT
#[macro_export]
macro_rules! lua_method_null {
    () => {
        ffi::lauxlib::luaL_Reg {
            name: ::std::ptr::null(),
            func: None,
        }
    };
}

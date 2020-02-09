pub use failure::Fail;
pub use failure::Error;
pub use failure::ResultExt;

// use luajit::ThreadStatus;

// #[derive(Debug, Fail)]
// enum MyError1 {
//     #[fail(display = "lua error: '{}', status: {:?}", message, status)]
//     LuaError {
//         status: ThreadStatus,
//         message: String,
//     },
//     #[fail(display = "option unwrapped to none")]
//     OptionNone,
// }

// impl From<(ThreadStatus, String)> for MyError1 {
//     fn from(i: (ThreadStatus, String)) -> Self {
//         MyError1::LuaError {
//             status: i.0,
//             message: i.1,
//         }
//     }
// }

// use std::option::NoneError;

// impl From<NoneError> for MyError1 {
//     fn from(err: NoneError) -> Self {
//         MyError1::OptionNone
//     }
// }

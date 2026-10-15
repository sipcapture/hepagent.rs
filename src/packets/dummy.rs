use pnet_macros::packet;

#[packet]
pub struct Dummy {
    #[payload]
    pub payload: Vec<u8>,
}

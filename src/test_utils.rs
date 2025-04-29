use chatterbox::message::Message;

#[allow(dead_code)]
pub fn get_test_message() -> Message<'static> {
    Message::new_now("unit-test", "".to_string())
}

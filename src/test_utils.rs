use chatterbox::message::Message;

#[allow(dead_code)]
pub fn get_test_message() -> Message {
    Message::new("unit-test".to_string(), "".to_string())
}

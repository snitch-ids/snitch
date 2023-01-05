use multi_dispatcher::message::Message;

#[allow(dead_code)]
pub fn get_test_message() -> Message {
    Message::new_now("unit-test".to_owned(), "".to_string())
}

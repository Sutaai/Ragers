pub struct User {
    pub alias: String,
    pub key: String,
}

impl Default for User {
    fn default() -> Self {
        Self {
            alias: "user".to_string(),
            key: "age14vhz9ffjt6r8tnct5zt8lv3hgrff238xra5s2jc0t3sckf0kpvesunyg5z".to_string(),
        }
    }
}

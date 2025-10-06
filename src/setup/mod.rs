pub struct DBSetupConfig {
    pub dbname: String,
    pub user: String,
    pub hashedpassword: String,
    pub host: String,
    pub port: u16,
}

pub fn setup() {
    println!("Setting up the password manager...");
}
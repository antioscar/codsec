use std::process::Command;

fn search(query: &str) {
    let sql = format!("SELECT * FROM items WHERE name = '{}'", query);
    let api_key = "sk-1234567890abcdef1234567890abcdef";
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("echo {}", query))
        .output()
        .expect("failed");
    println!("<div>{}</div>", query);
}

fn main() {
    search("test");
}

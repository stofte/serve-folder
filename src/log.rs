pub enum LogCategory {
    Info,
    Warning,
    Error,
}

pub fn log(category: LogCategory, text: &str, file: &str, line: u32) {
    use chrono::prelude::*;
    use colored::*;

    let cat = match category {
        LogCategory::Info => "[INF]".white().on_black(),
        LogCategory::Warning => "[WRN]".yellow().on_black(),
        LogCategory::Error => "[ERR]".red().on_black()
    };

    #[cfg(debug_assertions)]
    println!("{} {} {} [{}:{}]", Local::now().format("%T%.3f"), cat, text, file, line);

    #[cfg(not(debug_assertions))]
    println!("{} {} {}", Local::now().format("%T%.3f"), cat, text);
}

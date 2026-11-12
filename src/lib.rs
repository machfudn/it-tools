pub const APP_NAME: &str = "it-tools";
pub const APP_BANNER_WIDTH: usize = 73;
pub const APP_BANNER: &str = r#" ______  ________                ________                   __
/      |/        |              /        |                 /  |
$$$$$$/ $$$$$$$$/               $$$$$$$$/______    ______  $$ |  _______
  $$ |     $$ |       ______       $$ | /      \  /      \ $$ | /       |
  $$ |     $$ |      /      |      $$ |/$$$$$$  |/$$$$$$  |$$ |/$$$$$$$/
  $$ |     $$ |      $$$$$$/       $$ |$$ |  $$ |$$ |  $$ |$$ |$$      \
 _$$ |_    $$ |                    $$ |$$ \__$$ |$$ \__$$ |$$ | $$$$$$  |
/ $$   |   $$ |                    $$ |$$    $$/ $$    $$/ $$ |/     $$/
$$$$$$/    $$/                     $$/  $$$$$$/   $$$$$$/  $$/ $$$$$$$/"#;

pub mod backup;
pub mod cli;
pub mod config;
pub mod engine;
pub mod platform;
pub mod rules;
pub mod tui;
pub mod update;

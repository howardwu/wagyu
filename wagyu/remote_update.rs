use tokio::runtime::Runtime;
use reqwest;
use serde_json;
use serde_json::Value;
use self_update;

use clap::{crate_version};

const APP_VERSION: &str = crate_version!();
const VAPP_VERSION: &str = concat!("v", crate_version!());
const REPO_OWNER: &str  = "AleoHQ";
const REPO_NAME: &str  = "wagyu";

#[cfg_attr(tarpaulin, skip)]
pub async fn get_api(url: String) -> Result<String, reqwest::Error> {
    let client = reqwest::Client::new();
    let res = client.get(&url[..])
                    .header("User-Agent", "request")
                    .send()
                    .await?;

    Ok(res.text().await?)
}

#[cfg_attr(tarpaulin, skip)]
pub async fn get_latest_version() -> Result<String, reqwest::Error> {
    match get_api( format!("https://api.github.com/repos/{}/{}/releases/latest", REPO_OWNER, REPO_NAME) ).await {
        Ok(response) => {
            let json_data: Value = serde_json::from_str(String::as_str(&response)).unwrap();
            match Value::as_str(&json_data["tag_name"]) {
                Some(version) => Ok(String::from(version)),
                None          => Ok(String::from(""))
            }
        },
        Err(err) => Err(err)
    }
}

#[cfg_attr(tarpaulin, skip)]
pub fn version_check() -> String {
    match Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(get_latest_version()) {
        Ok(version) => {
            if &version[..] == "" {
                println!("Auto Update API limit exceeded.");
            } else if &version[..] > VAPP_VERSION {
                println!("New version {} available.", version);
                return version;
            } else {
                println!("You are using the latest version.");
            }
        }
        Err(_) => println!("Please check the internet connection for the automatic version update.")
    }
    return String::from("");
}

#[cfg_attr(tarpaulin, skip)]
pub fn update() -> Result<(), Box<dyn(::std::error::Error)>> {
    println!("Upgrading version...");

    let bin_name = std::env::current_exe()
        .expect("Can't get the exec path")
        .file_name()
        .expect("Can't get the exec name")
        .to_string_lossy()
        .into_owned();

    let status = self_update::backends::github::Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name(&bin_name[..])
        .show_download_progress(true)
        .current_version(APP_VERSION)
        .build()?
        .update()?;

    println!("Update status: `{}`!", status.version());

    Ok(())
}

#[cfg_attr(tarpaulin, skip)]
pub fn run() {
    match update() {
        Ok(_) => println!("Update finished."),
        Err(err) => println!("{}\nUpdate failed.", err)
    }
}
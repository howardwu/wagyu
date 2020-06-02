use crate::cli::{types::*, CLIError, CLI};

use clap::{ArgMatches, crate_version};
use reqwest;
use self_update;
use serde::{Serialize};
use serde_json::{from_str, Value};
use tokio::runtime::Runtime;

const APP_VERSION: &str = crate_version!();
const VAPP_VERSION: &str = concat!("v", crate_version!());
const REPO_OWNER: &str  = "AleoHQ";
const REPO_NAME: &str  = "wagyu";

#[derive(Clone, Debug, Serialize)]
pub struct UpdateOptions {

}

impl Default for UpdateOptions {
    fn default() -> Self {
        Self {

        }
    }
}

pub struct UpdateCLI;

impl CLI for UpdateCLI {
    type Options = UpdateOptions;

    const NAME: NameType = "update";
    const ABOUT: AboutType = "Update wagyu to the latest version";
    const FLAGS: &'static [FlagType] = &[];
    const OPTIONS: &'static [OptionType] = &[];
    const SUBCOMMANDS: &'static [SubCommandType] = &[];

    /// Handle all CLI arguments and flags for Update
    #[cfg_attr(tarpaulin, skip)]
    fn parse(_arguments: &ArgMatches) -> Result<Self::Options, CLIError> {
        let options = UpdateOptions::default();

        Ok(options)
    }

    /// Automatic Update
    #[cfg_attr(tarpaulin, skip)]
    fn print(options: Self::Options) -> Result<(), CLIError> {
        fn output(_options: UpdateOptions) -> Result<(), CLIError> {
            match UpdateCLI::update() {
                Ok(_) => println!("Update finished."),
                Err(err) => println!("{}\nUpdate failed.", err)
            }

            Ok(())
        }
        
        output(options)
    }
}

impl UpdateCLI {
    
    /// Handle API call
    #[cfg_attr(tarpaulin, skip)]
    pub async fn get_api(url: String) -> Result<String, reqwest::Error> {
        let client = reqwest::Client::new();
        let res = client.get(&url[..])
                        .header("User-Agent", "request")
                        .send()
                        .await?;

        Ok(res.text().await?)
    }

    /// Get latest version of wagyu
    #[cfg_attr(tarpaulin, skip)]
    pub fn get_latest_version() -> Result<String, reqwest::Error> {
        match Runtime::new()
            .expect("Failed to create Tokio runtime")
            .block_on(Self::get_api( format!("https://api.github.com/repos/{}/{}/releases/latest", REPO_OWNER, REPO_NAME) )) {
            Ok(response) => {
                let json_data: Value = from_str(String::as_str(&response)).unwrap();
                match Value::as_str(&json_data["tag_name"]) {
                    Some(version) => Ok(String::from(version)),
                    None          => Ok(String::from(""))
                }
            },
            Err(err) => Err(err)
        }
    }

    /// Check latest version
    #[cfg_attr(tarpaulin, skip)]
    pub fn version_check() {
        match Self::get_latest_version() {
            Ok(version) => {
                if &version[..] == "" {
                    println!("Auto Update API limit exceeded.");
                } else if &version[..] > VAPP_VERSION {
                    println!("New version {} available.", version);
                } else {
                    println!("You are on the latest version.");
                }
            }
            Err(_) => println!("You are in offline mode.")
        }
    }

    /// Remote update to latest version
    #[cfg_attr(tarpaulin, skip)]
    pub fn update() -> Result<(), Box<dyn(::std::error::Error)>> {
        println!("Upgrading version...");

        let bin_name = std::env::current_exe()
            .expect("Can't get the bin path")
            .file_name()
            .expect("Can't get the bin name")
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
}

use std::{
    fs::OpenOptions,
    fs::{remove_file, File},
    io::{self, Write},
    path::PathBuf,
};

use crypto::{CipherConfig, CreateUserConfig};

mod crypto;

const ERROR_MESSAGE_SUFFIX: &str = "Use 'help' for more information.";

fn parse_arg(
    args: Vec<String>,
    arg: &str,
    long_arg: Option<&str>,
    default_value: Option<&str>,
) -> Result<String, String> {
    for i in 0..args.len() {
        if args[i] == arg {
            if i + 1 < args.len() {
                if args[i + 1].starts_with("-") {
                    return Err(format!("Invalid value for {}", arg));
                } else {
                    return Ok(args[i + 1].clone());
                }
            } else {
                return Err(format!("Value not provided for {}", arg));
            }
        } else if let Some(long_arg) = long_arg {
            if args[i] == long_arg {
                if i + 1 < args.len() {
                    if args[i + 1].starts_with("-") {
                        return Err(format!("Invalid value for {}", long_arg));
                    } else {
                        return Ok(args[i + 1].clone());
                    }
                } else {
                    return Err(format!("Value not provided for {}", long_arg));
                }
            }
        }
    }

    if let Some(default_value) = default_value {
        return Ok(default_value.to_string());
    }

    return Err(format!("Value not provided for {}", arg));
}

fn clear_file_contents(p: &PathBuf) -> io::Result<String> {
    let mut file = OpenOptions::new().write(true).truncate(true).open(p)?;
    file.write_all(b"")?;
    Ok("File cleared.".to_string())
}

fn clear_dir(p: &PathBuf) -> io::Result<String> {
    for entry in p.read_dir()? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Could not read directory",
                ))
            }
        };
        let path = entry.path();
        if path.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Directory contains subdirectories",
            ));
        } else {
            remove_file(&path)?;
        }
    }
    Ok("Directory cleared.".to_string())
}

fn help() -> String {
    let help = r#"Usage:
    kc_toolkit [command] [options]

Commands:
    create          Create a new user
        -u, --username  Username (default: user)
        -m, --master    Master password (default: master)
        -d, --domain    Domain (default: domain)
        -p, --password  Password (default: password)

    delete          Delete a user
        -u, --username  Username (required)

    check           Check if a user exists
        -u, --username  Username (required)

    read            Read a user
        -u, --username  Username (required)
        -m, --master    Master password (required)

    add-pwd         Add a password to a user
        -u, --username  Username (required)
        -m, --master    Master password (required)
        -d, --domain    Domain (required)
        -p, --password  Password (required)

    delete-pwd      Delete a password from a user
        -u, --username  Username (required)
        -m, --master    Master password (required)
        -d, --domain    Domain (required)

    modify-pwd     Modify a password from a user
        -u, --username  Username (required)
        -m, --master    Master password (required)
        -d, --domain    Domain (required)
        -p, --password  Password (required)

    clear           Clear all users

    help            Display this message
"#;
    help.to_string()
}

fn delete_user(p: &PathBuf, username: &str) -> io::Result<String> {
    let hash = crypto::hash(username.to_string());
    let file_path = p.join(hash.as_str());
    if file_path.exists() {
        remove_file(file_path)?;
        Ok("User deleted.".to_string())
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "User not found"))
    }
}

fn read_user(p: &PathBuf, username: &str, master_pwd: &str) -> Result<Vec<CipherConfig>, String> {
    let hash = crypto::hash(username.to_string());
    let file_path = p.join(hash.as_str());
    let mut data: Vec<CipherConfig> = Vec::new();
    if file_path.exists() {
        let mut bytes = std::fs::read(file_path).unwrap();
        let mut run = true;
        while run {
            let res = CipherConfig::read_from_bytes(bytes, master_pwd);
            if res.is_err() {
                return Err("Could not read user".to_string());
            }
            let (cipher, remaining) = res.unwrap();
            data.push(cipher);
            bytes = remaining;
            if bytes.len() == 0 {
                run = false;
            }
        }
    } else {
        return Err("User not found".to_string());
    }
    Ok(data)
}

fn check_user(p: &PathBuf, username: &str) -> io::Result<String> {
    let hash = crypto::hash(username.to_string());
    let file_path = p.join(hash.as_str());
    if file_path.exists() {
        Ok("User exists.".to_string())
    } else {
        Ok("User does not exist.".to_string())
    }
}

pub fn parse_args(args: Vec<String>) -> Result<String, String> {
    let command = &args[0];
    match command.as_str() {
        "create" => {
            let username = parse_arg(args.clone(), "-u", Some("--username"), Some("user"));
            let master_pwd = parse_arg(args.clone(), "-m", Some("--master"), Some("master"));
            let domain = parse_arg(args.clone(), "-d", Some("--domain"), Some("domain"));
            let pwd = parse_arg(args.clone(), "-p", Some("--password"), Some("password"));
            if username.is_err() {
                return Err(username.unwrap_err());
            }
            if master_pwd.is_err() {
                return Err(master_pwd.unwrap_err());
            }
            if domain.is_err() {
                return Err(domain.unwrap_err());
            }
            if pwd.is_err() {
                return Err(pwd.unwrap_err());
            }
            dotenv::dotenv().ok();
            let path = dotenv::var("KEEPER_CRABBY_DATA").unwrap_or("".to_string());
            let path = PathBuf::from(path);
            let username = username.unwrap();
            let master_pwd = master_pwd.unwrap();
            let domain = domain.unwrap();
            let pwd = pwd.unwrap();
            let config = CreateUserConfig::new(
                username.as_str(),
                master_pwd.as_str(),
                domain.as_str(),
                pwd.as_str(),
                path,
            );
            let res = config.create_user();
            match res {
                Ok(_) => return Ok("User created.".to_string()),
                Err(e) => return Err(e),
            }
        }
        "delete" => {
            dotenv::dotenv().ok();
            let path = dotenv::var("KEEPER_CRABBY_DATA").unwrap_or("".to_string());
            let path = PathBuf::from(path);
            let username = parse_arg(args.clone(), "-u", Some("--username"), None);
            if username.is_err() {
                return Err(username.unwrap_err());
            }
            let res = delete_user(&path, &username.unwrap());
            match res {
                Ok(_) => return Ok("User deleted.".to_string()),
                Err(e) => return Err(e.to_string()),
            }
        }
        "check" => {
            dotenv::dotenv().ok();
            let path = dotenv::var("KEEPER_CRABBY_DATA").unwrap_or("".to_string());
            let path = PathBuf::from(path);
            let username = parse_arg(args.clone(), "-u", Some("--username"), None);
            if username.is_err() {
                return Err(username.unwrap_err());
            }
            let res = check_user(&path, &username.unwrap());
            match res {
                Ok(o) => return Ok(o.to_string()),
                Err(e) => return Err(e.to_string()),
            }
        }
        "read" => {
            dotenv::dotenv().ok();
            let path = dotenv::var("KEEPER_CRABBY_DATA").unwrap_or("".to_string());
            let path = PathBuf::from(path);
            let username = parse_arg(args.clone(), "-u", Some("--username"), None);
            let master_pwd = parse_arg(args.clone(), "-m", Some("--master"), None);
            if username.is_err() {
                return Err(username.unwrap_err());
            }
            if master_pwd.is_err() {
                return Err(master_pwd.unwrap_err());
            }
            let res = read_user(&path, &username.unwrap(), &master_pwd.unwrap());
            match res {
                Ok(r) => {
                    let mut data: String = String::new();
                    for cipher in r {
                        let result = cipher.decrypt_data();
                        match result {
                            Ok(d) => {
                                data.push_str(d.as_str());
                                data.push_str("\n");
                            }
                            Err(_) => return Err("Could not read user".to_string()),
                        }
                    }
                    return Ok(data);
                }
                Err(e) => return Err(e),
            }
        }
        "add-pwd" => {
            dotenv::dotenv().ok();
            let path = dotenv::var("KEEPER_CRABBY_DATA").unwrap_or("".to_string());
            let path = PathBuf::from(path);
            let username = parse_arg(args.clone(), "-u", Some("--username"), None);
            let master_pwd = parse_arg(args.clone(), "-m", Some("--master"), None);
            let domain = parse_arg(args.clone(), "-d", Some("--domain"), None);
            let pwd = parse_arg(args.clone(), "-p", Some("--password"), None);
            if username.is_err() {
                return Err(username.unwrap_err());
            }
            if master_pwd.is_err() {
                return Err(master_pwd.unwrap_err());
            }
            if domain.is_err() {
                return Err(domain.unwrap_err());
            }
            if pwd.is_err() {
                return Err(pwd.unwrap_err());
            }
            let username = username.unwrap();
            let master_pwd = master_pwd.unwrap();
            let domain = domain.unwrap();
            let pwd = pwd.unwrap();
            let hash = crypto::hash(username.to_string());
            let file_path = path.join(hash.as_str());
            if !file_path.exists() {
                return Err("User does not exist".to_string());
            }
            let data = read_user(&path, &username, &master_pwd);
            match data {
                Ok(d) => {
                    for c in d {
                        let result = c.decrypt_data();
                        match result {
                            Ok(d) => {
                                let curr_domain = d.split_whitespace().next().unwrap();
                                if domain == curr_domain {
                                    return Err("Domain already exists".to_string());
                                }
                            }
                            Err(_) => return Err("Wrong master password inserted".to_string()),
                        }
                    }
                }
                Err(_) => return Err("Wrong master password inserted".to_string()),
            }
            let data = format!("{} {}", domain, pwd);
            let cipher = CipherConfig::encrypt_data(&data, &master_pwd);
            match cipher {
                Ok(c) => {
                    let res = c.write_to_file(file_path);
                    match res {
                        Ok(_) => return Ok("Password added.".to_string()),
                        Err(_) => return Err("Could not add password".to_string()),
                    }
                }
                Err(_) => return Err("Could not add password".to_string()),
            }
        }
        "delete-pwd" => {
            dotenv::dotenv().ok();
            let path = dotenv::var("KEEPER_CRABBY_DATA").unwrap_or("".to_string());
            let path = PathBuf::from(path);
            let username = parse_arg(args.clone(), "-u", Some("--username"), None);
            let master_pwd = parse_arg(args.clone(), "-m", Some("--master"), None);
            let domain = parse_arg(args.clone(), "-d", Some("--domain"), None);
            if username.is_err() {
                return Err(username.unwrap_err());
            }
            if master_pwd.is_err() {
                return Err(master_pwd.unwrap_err());
            }
            if domain.is_err() {
                return Err(domain.unwrap_err());
            }
            let username = username.unwrap();
            let master_pwd = master_pwd.unwrap();
            let domain = domain.unwrap();
            let hash = crypto::hash(username.to_string());
            let file_path = path.join(hash.as_str());
            if !file_path.exists() {
                return Err("User does not exist".to_string());
            }
            let data = read_user(&path, &username, &master_pwd);
            match data {
                Ok(d) => {
                    let mut new_data: Vec<CipherConfig> = Vec::new();
                    let mut found = false;
                    for c in d {
                        let result = c.decrypt_data();
                        match result {
                            Ok(d) => {
                                let curr_domain = d.split_whitespace().next().unwrap();
                                if domain == curr_domain {
                                    found = true;
                                } else {
                                    new_data.push(c);
                                }
                            }
                            Err(_) => return Err("Wrong master password inserted".to_string()),
                        }
                    }
                    if !found {
                        return Err("Domain not found".to_string());
                    }
                    let file_rem_res = clear_file_contents(&file_path);
                    match file_rem_res {
                        Ok(_) => {}
                        Err(_) => return Err("Could not delete password".to_string()),
                    }
                    for c in new_data {
                        let res = c.write_to_file(file_path.clone());
                        match res {
                            Ok(_) => continue,
                            Err(_) => return Err("Could not delete password".to_string()),
                        }
                    }
                    return Ok("Password deleted.".to_string());
                }
                Err(_) => return Err("Wrong master password inserted".to_string()),
            }
        }
        "modify-pwd" => {
            dotenv::dotenv().ok();
            let path = dotenv::var("KEEPER_CRABBY_DATA").unwrap_or("".to_string());
            let path = PathBuf::from(path);
            let username = parse_arg(args.clone(), "-u", Some("--username"), None);
            let master_pwd = parse_arg(args.clone(), "-m", Some("--master"), None);
            let domain = parse_arg(args.clone(), "-d", Some("--domain"), None);
            let pwd = parse_arg(args.clone(), "-p", Some("--password"), None);
            if username.is_err() {
                return Err(username.unwrap_err());
            }
            if master_pwd.is_err() {
                return Err(master_pwd.unwrap_err());
            }
            if domain.is_err() {
                return Err(domain.unwrap_err());
            }
            if pwd.is_err() {
                return Err(pwd.unwrap_err());
            }
            let username = username.unwrap();
            let master_pwd = master_pwd.unwrap();
            let domain = domain.unwrap();
            let pwd = pwd.unwrap();
            let hash = crypto::hash(username.to_string());
            let file_path = path.join(hash.as_str());
            if !file_path.exists() {
                return Err("User does not exist".to_string());
            }
            let data = read_user(&path, &username, &master_pwd);
            match data {
                Ok(d) => {
                    let mut new_data: Vec<CipherConfig> = Vec::new();
                    let mut found = false;
                    for c in d {
                        let result = c.decrypt_data();
                        match result {
                            Ok(d) => {
                                let curr_domain = d.split_whitespace().next().unwrap();
                                if domain == curr_domain {
                                    let new_pair = format!("{} {}", domain, pwd);
                                    let cipher = CipherConfig::encrypt_data(&new_pair, &master_pwd);
                                    match cipher {
                                        Ok(c) => {
                                            new_data.push(c);
                                            found = true;
                                        }
                                        Err(_) => {
                                            return Err("Could not modify password".to_string())
                                        }
                                    }
                                } else {
                                    new_data.push(c);
                                }
                            }
                            Err(_) => return Err("Wrong master password inserted".to_string()),
                        }
                    }
                    if !found {
                        return Err("Domain not found".to_string());
                    }
                    let file_rem_res = clear_file_contents(&file_path);
                    match file_rem_res {
                        Ok(_) => {}
                        Err(_) => return Err("Could not modify password".to_string()),
                    }
                    for c in new_data {
                        let res = c.write_to_file(file_path.clone());
                        match res {
                            Ok(_) => continue,
                            Err(_) => return Err("Could not modify password".to_string()),
                        }
                    }
                    return Ok("Password modified.".to_string());
                }
                Err(_) => return Err("Wrong master password inserted".to_string()),
            }
        }
        "clear" => {
            dotenv::dotenv().ok();
            let path = dotenv::var("KEEPER_CRABBY_DATA").unwrap_or("".to_string());
            let path = PathBuf::from(path);
            let res = clear_dir(&path);
            match res {
                Ok(_) => return Ok("Directory cleared.".to_string()),
                Err(e) => return Err(e.to_string()),
            }
        }
        "help" => {
            return Ok(help());
        }
        _ => {
            return Err("Invalid command".to_string());
        }
    }
}

pub fn error(err: &str) -> String {
    format!("Error: {}. {}", err, ERROR_MESSAGE_SUFFIX)
}

pub fn create_file(p: &PathBuf, file_name: &str) -> io::Result<PathBuf> {
    let file_path = p.join(file_name);
    if !file_path.exists() {
        File::create(file_path.as_path())?;
        return Ok(file_path);
    } else {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "File already exists",
        ));
    }
}

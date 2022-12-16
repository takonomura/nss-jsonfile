extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

use serde::Deserialize;
use std::fs::File;
use std::io::{ErrorKind,BufReader};
use std::error::Error;
use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::group::{Group, GroupHooks};

#[derive(Deserialize, Debug)]
struct JsonPasswd {
    name: String,
    passwd: Option<String>,
    uid: u32,
    gid: Option<u32>,
    gecos: Option<String>,
    dir: String,
    shell: String,
}

impl JsonPasswd {
    pub fn to_nss(self) -> Passwd {
        Passwd {
            name: self.name,
            passwd: self.passwd.unwrap_or("*".to_string()),
            uid: self.uid,
            gid: self.gid.unwrap_or(self.uid),
            gecos: self.gecos.unwrap_or_default(),
            dir: self.dir,
            shell: self.shell,
        }
    }
}

fn load_passwd() -> Result<Vec<JsonPasswd>, Box<dyn Error>> {
    let f = match File::open("/etc/passwd.json") {
        Ok(f) => f,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(vec![]),
        Err(err) => return Err(Box::new(err)),
    };
    let r = BufReader::new(f);
    let passwd = serde_json::from_reader(r)?;

    Ok(passwd)
}

#[derive(Deserialize, Debug)]
struct JsonGroup {
    name: String,
    passwd: Option<String>,
    gid: u32,
    members: Vec<String>,
}

impl JsonGroup {
    pub fn to_nss(self) -> Group {
        Group {
            name: self.name,
            passwd: self.passwd.unwrap_or("*".to_string()),
            gid: self.gid,
            members: self.members,
        }
    }
}

fn load_groups() -> Result<Vec<JsonGroup>, Box<dyn Error>> {
    let mut groups: Vec<JsonGroup> = match File::open("/etc/group.json") {
        Ok(f) => serde_json::from_reader(BufReader::new(f))?,
        Err(err) if err.kind() == ErrorKind::NotFound => vec![],
        Err(err) => return Err(Box::new(err)),
    };

    groups.extend(load_passwd()?.into_iter()
        .filter(|u| u.gid.is_none())
        .map(|u| JsonGroup{
            name: u.name.clone(),
            passwd: None,
            gid: u.uid,
            members: vec![u.name],
        }));

    Ok(groups)
}

struct JsonFilePasswd;
libnss_passwd_hooks!(jsonfile, JsonFilePasswd);

impl PasswdHooks for JsonFilePasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        let v = match load_passwd() {
            Err(_) => return Response::Unavail,
            Ok(v) => v,
        };
        let r = v.into_iter().map(|u| u.to_nss()).collect();
        Response::Success(r)
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        let v = match load_passwd() {
            Err(_) => return Response::Unavail,
            Ok(v) => v,
        };
        match v.into_iter().find(|u| u.uid == uid) {
            None => Response::NotFound,
            Some(u) => Response::Success(u.to_nss()),
        }
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        let v = match load_passwd() {
            Err(_) => return Response::Unavail,
            Ok(v) => v,
        };
        match v.into_iter().find(|u| u.name == name) {
            None => Response::NotFound,
            Some(u) => Response::Success(u.to_nss()),
        }
    }
}

struct JsonFileGroup;
libnss_group_hooks!(jsonfile, JsonFileGroup);

impl GroupHooks for JsonFileGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        let v = match load_groups() {
            Err(_) => return Response::Unavail,
            Ok(v) => v,
        };
        let r = v.into_iter().map(|g| g.to_nss()).collect();
        Response::Success(r)
    }

    fn get_entry_by_gid(gid: libc::uid_t) -> Response<Group> {
        let v = match load_groups() {
            Err(_) => return Response::Unavail,
            Ok(v) => v,
        };
        match v.into_iter().find(|g| g.gid == gid) {
            None => Response::NotFound,
            Some(g) => Response::Success(g.to_nss()),
        }
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        let v = match load_groups() {
            Err(_) => return Response::Unavail,
            Ok(v) => v,
        };
        match v.into_iter().find(|g| g.name == name) {
            None => Response::NotFound,
            Some(g) => Response::Success(g.to_nss()),
        }
    }
}

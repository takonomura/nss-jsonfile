extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};

struct JsonFilePasswd;
libnss_passwd_hooks!(jsonfile, JsonFilePasswd);

impl PasswdHooks for JsonFilePasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        Response::Success(vec![])
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        Response::NotFound
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        Response::NotFound
    }
}

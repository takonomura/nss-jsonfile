# nss-jsonfile

`nss-jsonfile` is an NSS module that provides users and groups from local JSON
files instead of `/etc/passwd` and `/etc/group`-style files.

It only reads local files. Fetching or generating those files is intentionally
left to another tool, such as `curl` from cron or a configuration management
system.

Make sure `/etc/passwd.json` and `/etc/group.json` are owned and writable only
by trusted administrators. This module does not validate file permissions, so
overly broad write access can allow local users to affect NSS results.

## Installation

Download the shared library from the
[releases](https://github.com/takonomura/nss-jsonfile/releases), then install it
as `libnss_jsonfile.so.2` in a directory searched by the system dynamic linker.
The exact directory depends on the distribution; common locations include
`/lib/x86_64-linux-gnu`, `/usr/lib/x86_64-linux-gnu`, and `/usr/lib64`.

Then enable it in `/etc/nsswitch.conf`:

```text
passwd:     files jsonfile
group:      files jsonfile
initgroups: files jsonfile
```

`initgroups` is only needed when using the `groups` field in `passwd.json` or
the `members` field in `group.json`.

You may need to run `ldconfig` after installing the library.

## Files

Users are read from `/etc/passwd.json`:

```json
[
  {
    "name": "test",
    "uid": 2001,
    "dir": "/home/test",
    "shell": "/bin/bash",
    "groups": [27]
  }
]
```

Fields:

- `name` (required)
- `passwd` (optional, defaults to `*`)
- `uid` (required)
- `gid` (optional, defaults to `uid`)
- `gecos` (optional, defaults to an empty string)
- `dir` (required)
- `shell` (required)
- `groups` (optional list of extra group IDs for `initgroups`)

If `gid` is omitted, `nss-jsonfile` also exposes a group with the same name and
ID as the user.

Additional groups are read from `/etc/group.json`:

```json
[
  {
    "name": "testgroup",
    "gid": 1234,
    "members": ["test"]
  }
]
```

Fields:

- `name` (required)
- `passwd` (optional, defaults to `*`)
- `gid` (required)
- `members` (optional)

Unknown JSON fields are ignored, so the same files can contain data for other
tools.

## License

LGPL-3.0

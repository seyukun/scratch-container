use nix::unistd::{self, Pid};
use std::{env, error::Error, fs};

#[allow(dead_code)]
pub struct SysProcIdMap {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

pub fn apply(pid: Pid) -> Result<(), Box<dyn Error>> {
    let (uid_mappings, gid_mappings) = mappings()?;

    let uid_map = uid_mappings
        .iter()
        .map(|map| format!("{} {} {}\n", map.container_id, map.host_id, map.size))
        .collect::<String>();
    let gid_map = gid_mappings
        .iter()
        .map(|map| format!("{} {} {}\n", map.container_id, map.host_id, map.size))
        .collect::<String>();

    fs::write(format!("/proc/{pid}/setgroups"), "allow")?;
    fs::write(format!("/proc/{pid}/uid_map"), uid_map)?;
    fs::write(format!("/proc/{pid}/gid_map"), gid_map)?;

    Ok(())
}

fn mappings() -> Result<(Vec<SysProcIdMap>, Vec<SysProcIdMap>), Box<dyn Error>> {
    let host_uid = host_uid()?;
    let host_gid = host_gid()?;

    let user = match env::var("SUDO_USER") {
        Ok(sudo_user) => sudo_user,
        Err(_) => match env::var("USER") {
            Ok(user) => user,
            Err(_) => return Err("SUDO_USER or USER is required for subuid/subgid lookup".into()),
        },
    };

    let (sub_uid_start, sub_uid_size) = sub_id_range("/etc/subuid", &user)?;
    let (sub_gid_start, sub_gid_size) = sub_id_range("/etc/subgid", &user)?;

    let uid_size = sub_uid_size - 1;
    let gid_size = sub_gid_size - 1;
    if uid_size < 65534 || gid_size < 65534 {
        return Err(format!("subuid/subgid range for {user:?} is too small").into());
    }

    let uid_mappings = vec![
        SysProcIdMap {
            container_id: 0,
            host_id: host_uid.into(),
            size: 1,
        },
        SysProcIdMap {
            container_id: 1,
            host_id: sub_uid_start.into(),
            size: uid_size,
        },
    ];
    let gid_mappings = vec![
        SysProcIdMap {
            container_id: 0,
            host_id: host_gid.into(),
            size: 1,
        },
        SysProcIdMap {
            container_id: 1,
            host_id: sub_gid_start.into(),
            size: gid_size,
        },
    ];

    Ok((uid_mappings, gid_mappings))
}

fn host_uid() -> Result<unistd::Uid, String> {
    let mut host_uid = unistd::getuid();

    if let Ok(sudo_uid) = env::var("SUDO_UID") {
        host_uid = match sudo_uid.parse() {
            Ok(uid) => unistd::Uid::from_raw(uid),
            Err(err) => return Err(format!("parse SUDO_UID: {err}").into()),
        };
    }

    Ok(host_uid)
}

fn host_gid() -> Result<unistd::Gid, String> {
    let mut host_gid = unistd::getgid();

    if let Ok(sudo_gid) = env::var("SUDO_GID") {
        host_gid = match sudo_gid.parse() {
            Ok(gid) => unistd::Gid::from_raw(gid),
            Err(err) => return Err(format!("parse SUDO_GID: {err}").into()),
        };
    }

    Ok(host_gid)
}

fn sub_id_range(path: &str, name: &str) -> Result<(u32, u32), Box<dyn Error>> {
    let data = fs::read_to_string(path)?;

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 3 || fields[0] != name {
            continue;
        }

        return Ok((
            match fields[1].parse() {
                Ok(start) => start,
                Err(err) => return Err(format!("parse {path} start for {name:?}: {err}").into()),
            },
            match fields[2].parse() {
                Ok(size) => size,
                Err(err) => return Err(format!("parse {path} size for {name:?}: {err}").into()),
            },
        ));
    }

    Err(format!("{path} has no entry for {name:?}").into())
}

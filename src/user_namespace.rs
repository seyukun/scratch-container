use std::{env, error::Error, fs};

#[allow(dead_code)]
pub struct SysProcIdMap {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

pub fn mappings() -> Result<(Vec<SysProcIdMap>, Vec<SysProcIdMap>), Box<dyn Error>> {
    let host_uid = host_uid()?;
    let host_gid = host_gid()?;

    let user = env::var("SUDO_USER")
        .or_else(|_| env::var("USER"))
        .map_err(|_| "SUDO_USER or USER is required for subuid/subgid lookup")?;

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
            host_id: host_uid,
            size: 1,
        },
        SysProcIdMap {
            container_id: 1,
            host_id: sub_uid_start,
            size: uid_size,
        },
    ];
    let gid_mappings = vec![
        SysProcIdMap {
            container_id: 0,
            host_id: host_gid,
            size: 1,
        },
        SysProcIdMap {
            container_id: 1,
            host_id: sub_gid_start,
            size: gid_size,
        },
    ];

    Ok((uid_mappings, gid_mappings))
}

fn host_uid() -> Result<u32, String> {
    let mut host_uid = unsafe { libc::getuid() };

    if let Ok(sudo_uid) = env::var("SUDO_UID") {
        host_uid = sudo_uid
            .parse()
            .map_err(|err| format!("parse SUDO_UID: {err}"))?;
    }

    Ok(host_uid)
}

fn host_gid() -> Result<u32, String> {
    let mut host_gid = unsafe { libc::getgid() };

    if let Ok(sudo_gid) = env::var("SUDO_GID") {
        host_gid = sudo_gid
            .parse()
            .map_err(|err| format!("parse SUDO_GID: {err}"))?;
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

        let start = fields[1]
            .parse()
            .map_err(|err| format!("parse {path} start for {name:?}: {err}"))?;

        let size = fields[2]
            .parse()
            .map_err(|err| format!("parse {path} size for {name:?}: {err}"))?;

        return Ok((start, size));
    }

    Err(format!("{path} has no entry for {name:?}").into())
}

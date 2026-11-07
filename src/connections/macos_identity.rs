use crate::files::io_error;
use buntrail_core::contracts::{CoreError, ErrorCode};
use std::{
    fs::OpenOptions,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

pub(super) fn filesystem_namespace() -> Result<Vec<u8>, CoreError> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/")
        .map_err(io_error)?;
    let before = root.metadata().map_err(io_error)?;
    if !before.is_dir() {
        return Err(unavailable());
    }
    let mut requested = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_RETURNED_ATTRS,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut attributes = [0u8; 40];
    // Fixed-width returned bitmap + UUID; metadata and attributes share this pinned root FD.
    let result = unsafe {
        libc::fgetattrlist(
            root.as_raw_fd(),
            (&mut requested as *mut libc::attrlist).cast(),
            attributes.as_mut_ptr().cast(),
            attributes.len(),
            libc::FSOPT_REPORT_FULLSIZE,
        )
    };
    if result != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let after = root.metadata().map_err(io_error)?;
    namespace_from_query(
        (before.dev(), before.ino()),
        (after.dev(), after.ino()),
        &attributes,
    )
}

fn unavailable() -> CoreError {
    CoreError::new(
        ErrorCode::Unavailable,
        "Persistent local filesystem identity is unavailable",
    )
}

fn namespace_from_query(
    before: (u64, u64),
    after: (u64, u64),
    attributes: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if before != after {
        return Err(CoreError::new(
            ErrorCode::TargetChanged,
            "Root filesystem changed during identity verification",
        ));
    }
    if before.1 == 0 || attributes.len() != 40 {
        return Err(unavailable());
    }
    let words: [u32; 6] = std::array::from_fn(|i| {
        u32::from_ne_bytes(attributes[i * 4..i * 4 + 4].try_into().unwrap())
    });
    if words
        != [
            40,
            libc::ATTR_CMN_RETURNED_ATTRS,
            libc::ATTR_VOL_UUID,
            0,
            0,
            0,
        ]
        || attributes[24..].iter().all(|byte| *byte == 0)
    {
        return Err(unavailable());
    }
    Ok([
        b"mfs1".as_slice(),
        &attributes[24..],
        &before.1.to_be_bytes(),
    ]
    .concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume_reply(uuid: [u8; 16]) -> Vec<u8> {
        [
            40u32.to_ne_bytes().as_slice(),
            libc::ATTR_CMN_RETURNED_ATTRS.to_ne_bytes().as_slice(),
            libc::ATTR_VOL_UUID.to_ne_bytes().as_slice(),
            &[0; 12],
            &uuid,
        ]
        .concat()
    }

    #[test]
    fn persistent_root_namespace_survives_observed_device_renumbering() {
        let attributes = volume_reply([7; 16]);
        let previous_boot = (16_777_233, 2);
        let current_boot = (16_777_236, 2);
        let saved = namespace_from_query(previous_boot, previous_boot, &attributes).unwrap();
        let reopened = namespace_from_query(current_boot, current_boot, &attributes).unwrap();
        assert_eq!(
            saved, reopened,
            "a mount device renumber must not change the verified persistent root"
        );
    }

    #[test]
    fn changed_volume_or_root_is_a_distinct_target() {
        let root = (16_777_236, 2);
        let original = namespace_from_query(root, root, &volume_reply([7; 16])).unwrap();
        assert_ne!(
            original,
            namespace_from_query(root, root, &volume_reply([8; 16])).unwrap()
        );
        let other_root = (root.0, 99);
        assert_ne!(
            original,
            namespace_from_query(other_root, other_root, &volume_reply([7; 16])).unwrap()
        );
    }

    #[test]
    fn missing_malformed_or_zero_uuid_never_falls_back_to_device_identity() {
        let root = (16_777_236, 2);
        let valid = volume_reply([7; 16]);
        let mut invalid = vec![
            vec![],
            valid[..39].to_vec(),
            [valid.as_slice(), &[0]].concat(),
            volume_reply([0; 16]),
        ];
        for word in 0..6 {
            let mut reply = valid.clone();
            reply[word * 4..word * 4 + 4].copy_from_slice(&123u32.to_ne_bytes());
            invalid.push(reply);
        }
        for reply in invalid {
            assert_eq!(
                namespace_from_query(root, root, &reply).unwrap_err().code,
                ErrorCode::Unavailable
            );
        }
        assert_eq!(
            namespace_from_query(root, (root.0 + 1, root.1), &valid)
                .unwrap_err()
                .code,
            ErrorCode::TargetChanged
        );
        assert_eq!(
            namespace_from_query(root, (root.0, root.1 + 1), &valid)
                .unwrap_err()
                .code,
            ErrorCode::TargetChanged
        );
    }

    #[test]
    fn actual_darwin_uuid_query_is_used_by_the_local_target() {
        let namespace = filesystem_namespace().unwrap();
        assert_eq!(namespace.len(), 28);
        assert_eq!(&namespace[..4], b"mfs1");
        assert_eq!(
            super::super::local::identity()
                .unwrap()
                .filesystem_namespace,
            namespace
        );
    }
}

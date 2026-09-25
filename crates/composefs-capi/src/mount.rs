use std::ffi::{CStr, CString, c_char, c_int};
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};

use libc::size_t;
use rustix::fs::{CWD, Mode, OFlags, open};

use crate::errno::set_errno;

#[repr(C)]
pub struct LcfsMountOptions {
    pub objdirs: *const *const c_char,
    pub n_objdirs: size_t,
    pub workdir: *const c_char,
    pub upperdir: *const c_char,
    pub expected_fsverity_digest: *const c_char,
    pub flags: u32,
    pub idmap_fd: c_int,
    pub image_mountdir: *const c_char,
    pub reserved: [u32; 4],
    pub reserved2: [*mut std::ffi::c_void; 4],
}

const LCFS_MOUNT_FLAGS_REQUIRE_VERITY: u32 = 1 << 0;
const LCFS_MOUNT_FLAGS_IDMAP: u32 = 1 << 3;
const LCFS_MOUNT_FLAGS_TRY_VERITY: u32 = 1 << 4;
const LCFS_MOUNT_FLAGS_MASK: u32 = (1 << 5) - 1;

/// `EWRONGVERITY` from lcfs-mount.h: the image's fs-verity digest doesn't
/// match `expected_fsverity_digest`.
const EWRONGVERITY: c_int = libc::EILSEQ;
/// `ENOVERITY` from lcfs-mount.h: the image has no fs-verity digest.
const ENOVERITY: c_int = libc::ENOTTY;
/// Longest digest accepted in `expected_fsverity_digest`, as in C.
const MAX_DIGEST_SIZE: usize = 64;

/// Parses a hex digest; None if it isn't an even number of hex digits
/// of at most [`MAX_DIGEST_SIZE`] bytes.
///
/// An empty string parses to an empty digest, which then never matches.
/// That's deliberately stricter than C, which treats an empty digest as
/// no digest and mounts without checking.
fn parse_hex_digest(hex: &[u8]) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) || hex.len() / 2 > MAX_DIGEST_SIZE {
        return None;
    }
    // Digit by digit: u8::from_str_radix() would also accept e.g. "+a".
    let digit = |c: u8| char::from(c).to_digit(16);
    hex.chunks(2)
        .map(|pair| Some((digit(pair[0])? << 4 | digit(pair[1])?) as u8))
        .collect()
}

/// Checks the options like the C library does before mounting, returning
/// the parsed expected image digest, if any, or an errno.
///
/// # Safety
///
/// `options` must be null or point to valid mount options.
unsafe fn validate_options(options: *const LcfsMountOptions) -> Result<Option<Vec<u8>>, c_int> {
    let Some(opts) = (unsafe { options.as_ref() }) else {
        return Ok(None);
    };
    if opts.flags & !LCFS_MOUNT_FLAGS_MASK != 0
        || opts.upperdir.is_null() != opts.workdir.is_null()
        || (opts.flags & LCFS_MOUNT_FLAGS_IDMAP != 0 && opts.idmap_fd < 0)
    {
        return Err(libc::EINVAL);
    }
    if opts.expected_fsverity_digest.is_null() {
        return Ok(None);
    }
    let hex = unsafe { CStr::from_ptr(opts.expected_fsverity_digest) };
    parse_hex_digest(hex.to_bytes())
        .map(Some)
        .ok_or(libc::EINVAL)
}

/// Checks the image's fs-verity digest (as measured by the kernel, like
/// the C library) against the expected one.
fn verify_image_digest(image: BorrowedFd<'_>, expected: &[u8]) -> Result<(), c_int> {
    use composefs::fsverity::{MeasureVerityError, Sha256HashValue, measure_verity};
    use zerocopy::IntoBytes;

    let found = measure_verity::<Sha256HashValue>(image).map_err(|e| match e {
        MeasureVerityError::VerityMissing | MeasureVerityError::FilesystemNotSupported => ENOVERITY,
        MeasureVerityError::InvalidDigestAlgorithm { .. }
        | MeasureVerityError::InvalidDigestSize { .. } => EWRONGVERITY,
        MeasureVerityError::Io(e) => match e.raw_os_error() {
            Some(libc::ENODATA | libc::EOPNOTSUPP | libc::ENOTTY) => ENOVERITY,
            Some(errno) => errno,
            None => libc::EIO,
        },
    })?;
    if found.as_bytes() == expected {
        Ok(())
    } else {
        Err(EWRONGVERITY)
    }
}

/// Opens a directory given in the mount options.
///
/// # Safety
///
/// `path` must be a valid C string.
unsafe fn open_dir(path: *const c_char, flags: OFlags) -> Result<OwnedFd, c_int> {
    let path = unsafe { CStr::from_ptr(path) };
    open(
        path,
        flags | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.raw_os_error())
}

fn io_error_to_errno(e: &std::io::Error) -> c_int {
    e.raw_os_error().unwrap_or(libc::EINVAL)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_mount_image(
    path: *const c_char,
    mountpoint: *const c_char,
    options: *mut LcfsMountOptions,
) -> c_int {
    if path.is_null() || mountpoint.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }

    // Like C, reject bad options before touching the image.
    if let Err(errno) = unsafe { validate_options(options) } {
        set_errno(errno);
        return -1;
    }

    unsafe {
        let path_cstr = CStr::from_ptr(path);

        let image_fd = match open(path_cstr, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()) {
            Ok(fd) => fd,
            Err(e) => {
                set_errno(e.raw_os_error());
                return -1;
            }
        };

        let raw_fd = rustix::fd::IntoRawFd::into_raw_fd(image_fd);
        let result = lcfs_mount_fd(raw_fd, mountpoint, options);
        libc::close(raw_fd);
        result
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_mount_fd(
    fd: c_int,
    mountpoint: *const c_char,
    options: *mut LcfsMountOptions,
) -> c_int {
    if fd < 0 || mountpoint.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }

    let expected_digest = match unsafe { validate_options(options) } {
        Ok(digest) => digest,
        Err(errno) => {
            set_errno(errno);
            return -1;
        }
    };

    unsafe {
        let mountpoint_cstr = CStr::from_ptr(mountpoint);

        let dup_fd = libc::dup(fd);
        if dup_fd < 0 {
            return -1;
        }
        let image_fd = OwnedFd::from_raw_fd(dup_fd);

        // Callers such as ostree-prepare-root rely on this check to only
        // mount the image they expect.
        if let Some(expected) = expected_digest
            && let Err(errno) = verify_image_digest(image_fd.as_fd(), &expected)
        {
            set_errno(errno);
            return -1;
        }

        let mut basedirs: Vec<CString> = Vec::new();
        if !options.is_null() {
            let opts = &*options;
            if !opts.objdirs.is_null() && opts.n_objdirs > 0 {
                for i in 0..opts.n_objdirs {
                    let dir_ptr = *opts.objdirs.add(i);
                    if !dir_ptr.is_null() {
                        basedirs.push(CStr::from_ptr(dir_ptr).to_owned());
                    }
                }
            }
        }

        let verity = if !options.is_null() {
            let opts = &*options;
            if (opts.flags & LCFS_MOUNT_FLAGS_REQUIRE_VERITY) != 0 {
                composefs::mount::VerityRequirement::Required
            } else if (opts.flags & LCFS_MOUNT_FLAGS_TRY_VERITY) != 0 {
                composefs::mount::VerityRequirement::Try
            } else {
                composefs::mount::VerityRequirement::Disabled
            }
        } else {
            composefs::mount::VerityRequirement::Disabled
        };

        if !basedirs.is_empty() {
            let mut basedir_fds: Vec<OwnedFd> = Vec::new();
            for dir in &basedirs {
                match open_dir(dir.as_ptr(), OFlags::RDONLY) {
                    Ok(fd) => basedir_fds.push(fd),
                    Err(errno) => {
                        set_errno(errno);
                        return -1;
                    }
                }
            }

            let borrowed: Vec<_> = basedir_fds.iter().map(|fd| fd.as_fd()).collect();
            let mut mount_options = composefs::mount::MountOptions::default();

            if !options.is_null() {
                let opts = &*options;
                if (opts.flags & LCFS_MOUNT_FLAGS_IDMAP) != 0 && opts.idmap_fd >= 0 {
                    let dup_idmap = libc::dup(opts.idmap_fd);
                    if dup_idmap < 0 {
                        return -1;
                    }
                    mount_options.set_idmap(OwnedFd::from_raw_fd(dup_idmap));
                }
            }

            // composefs_fsmount() mounts the EROFS image itself.
            match composefs::mount::composefs_fsmount(
                image_fd,
                "composefs",
                &borrowed,
                verity,
                &mount_options,
            ) {
                Ok(fs_fd) => {
                    if let Err(e) = composefs::mount::mount_at(&fs_fd, CWD, mountpoint_cstr) {
                        set_errno(e.raw_os_error());
                        return -1;
                    }
                }
                Err(e) => {
                    set_errno(io_error_to_errno(&e));
                    return -1;
                }
            }
        } else {
            let erofs_fd = match composefs::mount::erofs_mount(image_fd) {
                Ok(fd) => fd,
                Err(e) => {
                    set_errno(io_error_to_errno(&e));
                    return -1;
                }
            };
            if let Err(e) = composefs::mount::mount_at(&erofs_fd, CWD, mountpoint_cstr) {
                set_errno(e.raw_os_error());
                return -1;
            }
        }

        0
    }
}

use std::{io, thread, time::Duration};

#[cfg(unix)]
use libc::{EIO, EREMOTEIO, ESTALE};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    ERROR_BAD_NET_NAME, ERROR_BAD_NET_RESP, ERROR_BAD_NETPATH, ERROR_DEV_NOT_EXIST,
    ERROR_IO_PENDING, ERROR_NETNAME_DELETED, ERROR_NETWORK_ACCESS_DENIED, ERROR_NETWORK_BUSY,
    ERROR_NETWORK_UNREACHABLE, ERROR_NO_SYSTEM_RESOURCES, ERROR_OPERATION_ABORTED,
    ERROR_SEM_TIMEOUT, ERROR_SHARING_VIOLATION,
};

const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
];

pub fn retry_io<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    retry_io_with(&mut operation, &RETRY_DELAYS, &mut |delay| {
        thread::sleep(delay)
    })
}

fn retry_io_with<T>(
    operation: &mut impl FnMut() -> io::Result<T>,
    retry_delays: &[Duration],
    sleep: &mut impl FnMut(Duration),
) -> io::Result<T> {
    let mut retry_index = 0;
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if is_retryable_io_error(&error) && retry_index < retry_delays.len() => {
                sleep(retry_delays[retry_index]);
                retry_index += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

pub fn is_retryable_io_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::StaleNetworkFileHandle
            | io::ErrorKind::ResourceBusy
            | io::ErrorKind::WriteZero
            | io::ErrorKind::UnexpectedEof
    ) {
        return true;
    }

    is_retryable_raw_os_error(error)
}

// Network filesystems can expose transient failures as uncategorized raw errors.
#[cfg(unix)]
fn is_retryable_raw_os_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == EIO || code == EREMOTEIO || code == ESTALE)
}

#[cfg(windows)]
fn is_retryable_raw_os_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code as u32 == ERROR_BAD_NET_NAME
        || code as u32 == ERROR_BAD_NETPATH
        || code as u32 == ERROR_BAD_NET_RESP
        || code as u32 == ERROR_DEV_NOT_EXIST
        || code as u32 == ERROR_IO_PENDING
        || code as u32 == ERROR_NETNAME_DELETED
        || code as u32 == ERROR_NETWORK_ACCESS_DENIED
        || code as u32 == ERROR_NETWORK_BUSY
        || code as u32 == ERROR_NETWORK_UNREACHABLE
        || code as u32 == ERROR_NO_SYSTEM_RESOURCES
        || code as u32 == ERROR_OPERATION_ABORTED
        || code as u32 == ERROR_SEM_TIMEOUT
        || code as u32 == ERROR_SHARING_VIOLATION)
}

#[cfg(not(any(unix, windows)))]
fn is_retryable_raw_os_error(_error: &io::Error) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_transient_errors_until_success() {
        let delays = [Duration::ZERO, Duration::ZERO];
        let mut attempts = 0;
        let mut sleeps = Vec::new();
        let mut operation = || {
            attempts += 1;
            if attempts < 3 {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            } else {
                Ok("copied")
            }
        };
        let result = retry_io_with(&mut operation, &delays, &mut |delay| sleeps.push(delay));
        assert_eq!(result.unwrap(), "copied");
        assert_eq!(attempts, 3);
        assert_eq!(sleeps, delays);
    }

    #[test]
    fn stops_after_retry_budget() {
        let delays = [Duration::ZERO, Duration::ZERO];
        let mut attempts = 0;
        let mut sleeps = Vec::new();
        let mut operation = || -> io::Result<()> {
            attempts += 1;
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        };
        let result = retry_io_with(&mut operation, &delays, &mut |delay| sleeps.push(delay));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(attempts, delays.len() + 1);
        assert_eq!(sleeps, delays);
    }

    #[test]
    fn does_not_retry_permanent_errors() {
        let mut attempts = 0;
        let mut operation = || -> io::Result<()> {
            attempts += 1;
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        };
        let result = retry_io_with(&mut operation, &[Duration::ZERO], &mut |_| panic!("slept"));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn common_transient_error_kinds_are_retryable() {
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::NotConnected,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::NetworkDown,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::StaleNetworkFileHandle,
            io::ErrorKind::ResourceBusy,
            io::ErrorKind::WriteZero,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(is_retryable_io_error(&io::Error::from(kind)), "{kind:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn eagain_is_retryable() {
        let error = io::Error::from_raw_os_error(libc::EAGAIN);
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(is_retryable_io_error(&error));
    }

    #[cfg(unix)]
    #[test]
    fn uncategorized_unix_io_errors_are_retryable() {
        for code in [libc::EIO, libc::EREMOTEIO, libc::ESTALE] {
            assert!(is_retryable_io_error(&io::Error::from_raw_os_error(code)));
        }
    }

    #[cfg(windows)]
    #[test]
    fn uncategorized_windows_io_errors_are_retryable() {
        for code in [ERROR_BAD_NETPATH, ERROR_BAD_NET_NAME, ERROR_NETWORK_BUSY] {
            assert!(is_retryable_io_error(&io::Error::from_raw_os_error(
                code as i32
            )));
        }
    }
}

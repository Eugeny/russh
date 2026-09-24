#[derive(Debug, PartialEq)]
pub(crate) enum UsernameLookupError<E> {
    Api(E),
    Invalid,
}

pub(crate) fn resolve_username<E>(
    principal: Result<Vec<u8>, E>,
    local: impl FnOnce() -> Result<Vec<u8>, E>,
) -> Result<String, UsernameLookupError<E>> {
    if let Ok(buffer) = principal
        && let Some(username) = parse_username(buffer).map_err(|()| UsernameLookupError::Invalid)?
    {
        return Ok(username);
    }

    parse_username(local().map_err(UsernameLookupError::Api)?)
        .map_err(|()| UsernameLookupError::Invalid)?
        .ok_or(UsernameLookupError::Invalid)
}

fn parse_username(mut buffer: Vec<u8>) -> Result<Option<String>, ()> {
    if buffer.is_empty() {
        return Ok(None);
    }
    if buffer.last() != Some(&0) {
        return Err(());
    }
    while buffer.last() == Some(&0) {
        buffer.pop();
    }
    if buffer.contains(&0) {
        return Err(());
    }
    let mut username = String::from_utf8(buffer).map_err(|_| ())?;
    if let Some(at_index) = username.find('@') {
        username.truncate(at_index);
    }
    Ok((!username.is_empty()).then_some(username))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn strips_domain_and_all_trailing_padding() {
        for buffer in [b"alice@domain\0\0".as_slice(), b"alice\0", b"alice\0\0\0"] {
            assert_eq!(
                parse_username(buffer.to_vec()),
                Ok(Some("alice".to_owned()))
            );
        }
    }

    #[test]
    fn rejects_invalid_buffers() {
        for buffer in [b"alice".as_slice(), b"alice\0unexpected\0", &[0xff, 0]] {
            assert_eq!(parse_username(buffer.to_vec()), Err(()));
        }
    }

    #[test]
    fn valid_principal_does_not_lookup_local_name() {
        let called = Cell::new(false);
        let result = resolve_username::<()>(Ok(b"alice@domain\0\0".to_vec()), || {
            called.set(true);
            Err(())
        });
        assert_eq!(result, Ok("alice".to_owned()));
        assert!(!called.get());
    }

    #[test]
    fn falls_back_for_failed_or_empty_principal() {
        for principal in [
            Err(()),
            Ok(vec![]),
            Ok(vec![0, 0]),
            Ok(b"@domain\0".to_vec()),
        ] {
            assert_eq!(
                resolve_username(principal, || Ok(b"local_user\0\0\0".to_vec())),
                Ok("local_user".to_owned())
            );
        }
    }

    #[test]
    fn preserves_local_lookup_error() {
        assert_eq!(
            resolve_username(Err("principal"), || Err("local")),
            Err(UsernameLookupError::Api("local"))
        );
    }

    #[test]
    fn rejects_invalid_principal_without_fallback() {
        let called = Cell::new(false);
        let result = resolve_username::<()>(Ok(b"alice\0unexpected\0".to_vec()), || {
            called.set(true);
            Ok(b"local\0".to_vec())
        });
        assert_eq!(result, Err(UsernameLookupError::Invalid));
        assert!(!called.get());
    }

    #[test]
    fn rejects_empty_or_invalid_local_name() {
        for local in [vec![], vec![0, 0], vec![0xff, 0], b"alice".to_vec()] {
            assert_eq!(
                resolve_username(Err(()), || Ok(local)),
                Err(UsernameLookupError::Invalid)
            );
        }
    }
}

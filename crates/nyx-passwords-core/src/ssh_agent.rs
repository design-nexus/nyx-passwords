//! The SSH agent protocol (draft-miller-ssh-agent), the part an agent that only lists
//! keys and signs needs: reading a request and writing the answer. Framing only; the
//! signing is `ssh::sign`. Every length is checked against what's left and a maximum.

/// The largest request read: a sign request carries a key and the data to sign.
pub const MAX_FRAME: usize = 256 * 1024;

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Identities,
    Sign {
        key: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    /// Anything else (adding keys, locking, extensions): answered with failure.
    Other(u8),
}

/// One request's body (after its length): `None` when it's malformed.
pub fn parse(frame: &[u8]) -> Option<Request> {
    let (&kind, mut rest) = frame.split_first()?;
    match kind {
        REQUEST_IDENTITIES => rest.is_empty().then_some(Request::Identities),
        SIGN_REQUEST => {
            let key = string(&mut rest)?.to_vec();
            let data = string(&mut rest)?.to_vec();
            let flags = u32::from_be_bytes(take(&mut rest, 4)?.try_into().ok()?);
            rest.is_empty().then_some(Request::Sign { key, data, flags })
        }
        other => Some(Request::Other(other)),
    }
}

/// A frame's length from its first four bytes, if it's one this agent reads.
pub fn frame_len(prefix: [u8; 4]) -> Option<usize> {
    let n = u32::from_be_bytes(prefix) as usize;
    (1..=MAX_FRAME).contains(&n).then_some(n)
}

/// The keys offered: each key's public blob and a comment (the item's name).
pub fn identities(keys: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut body = vec![IDENTITIES_ANSWER];
    body.extend((keys.len() as u32).to_be_bytes());
    for (blob, comment) in keys {
        put_string(&mut body, blob);
        put_string(&mut body, comment.as_bytes());
    }
    framed(body)
}

/// A signature (`ssh::sign`'s output) as the answer to a sign request.
pub fn signed(signature: &[u8]) -> Vec<u8> {
    let mut body = vec![SIGN_RESPONSE];
    put_string(&mut body, signature);
    framed(body)
}

pub fn failure() -> Vec<u8> {
    framed(vec![FAILURE])
}

fn framed(body: Vec<u8>) -> Vec<u8> {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend(body);
    out
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if rest.len() < n {
        return None;
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Some(head)
}

fn string<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = u32::from_be_bytes(take(rest, 4)?.try_into().ok()?) as usize;
    take(rest, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_frame(key: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut body = vec![SIGN_REQUEST];
        put_string(&mut body, key);
        put_string(&mut body, data);
        body.extend(flags.to_be_bytes());
        body
    }

    #[test]
    fn requests() {
        assert_eq!(parse(&[REQUEST_IDENTITIES]), Some(Request::Identities));
        assert_eq!(parse(&[REQUEST_IDENTITIES, 0]), None);
        assert_eq!(
            parse(&sign_frame(b"key", b"data", 4)),
            Some(Request::Sign { key: b"key".to_vec(), data: b"data".to_vec(), flags: 4 })
        );
        let mut long = sign_frame(b"key", b"data", 0);
        long.push(1);
        assert_eq!(parse(&long), None, "trailing bytes");
        let mut short = sign_frame(b"key", b"data", 0);
        short.truncate(short.len() - 1);
        assert_eq!(parse(&short), None);
        assert_eq!(parse(&[SIGN_REQUEST, 0xff, 0xff, 0xff, 0xff]), None, "a length past the end");
        assert_eq!(parse(&[17, 1, 2]), Some(Request::Other(17)));
        assert_eq!(parse(&[]), None);
        assert_eq!(frame_len(0u32.to_be_bytes()), None);
        assert_eq!(frame_len((MAX_FRAME as u32 + 1).to_be_bytes()), None);
        assert_eq!(frame_len(5u32.to_be_bytes()), Some(5));
    }

    #[test]
    fn answers() {
        assert_eq!(failure(), [0, 0, 0, 1, FAILURE]);
        let list = identities(&[(b"blob".to_vec(), "Work".into())]);
        assert_eq!(&list[..5], &[0, 0, 0, 21, IDENTITIES_ANSWER]);
        assert_eq!(&list[5..9], &1u32.to_be_bytes());
        assert_eq!(signed(b"sig"), [0, 0, 0, 8, SIGN_RESPONSE, 0, 0, 0, 3, b's', b'i', b'g']);
    }

    #[test]
    fn signs_with_a_key_item() {
        let key = crate::ssh::generate();
        let blob = crate::ssh::public_blob(key.private.expose()).unwrap();
        let sig = crate::ssh::sign(key.private.expose(), b"session data", 0).unwrap();
        // The signature verifies against the listed public key.
        let public = ssh_key::PublicKey::from_bytes(&blob).unwrap();
        let decoded = <ssh_key::Signature as ssh_key::encoding::Decode>::decode(&mut sig.as_slice()).unwrap();
        use signature::Verifier;
        public.key_data().verify(b"session data", &decoded).unwrap();
        assert!(public.key_data().verify(b"other data", &decoded).is_err());
    }
}

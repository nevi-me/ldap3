use std::convert::AsRef;
use std::io;

use lber::common::TagClass;
use lber::structures::{OctetString, Sequence, Tag};

use futures::Future;
use tokio_service::Service;

use ldap::{next_req_controls, Ldap, LdapOp};
use result::{CompareResult, LdapResult};

impl Ldap {
    /// See [`LdapConn::compare()`](struct.LdapConn.html#method.compare).
    pub fn compare<B: AsRef<[u8]>>(
        &self,
        dn: &str,
        attr: &str,
        val: B,
    ) -> Box<Future<Item = CompareResult, Error = io::Error> + Send> {
        let req = Tag::Sequence(Sequence {
            id: 14,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(dn.as_bytes()),
                    ..Default::default()
                }),
                Tag::Sequence(Sequence {
                    inner: vec![
                        Tag::OctetString(OctetString {
                            inner: Vec::from(attr.as_bytes()),
                            ..Default::default()
                        }),
                        Tag::OctetString(OctetString {
                            inner: Vec::from(val.as_ref()),
                            ..Default::default()
                        }),
                    ],
                    ..Default::default()
                }),
            ],
        });

        let fut = self
            .call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|response| {
                let (mut result, controls) = (LdapResult::from(response.0), response.1);
                result.ctrls = controls;
                Ok(CompareResult(result))
            });

        Box::new(fut)
    }
}

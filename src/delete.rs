use std::io;

use lber::common::TagClass;
use lber::structures::{OctetString, Tag};

use futures::Future;
use tokio_service::Service;

use ldap::{next_req_controls, Ldap, LdapOp};
use result::LdapResult;

impl Ldap {
    /// See [`LdapConn::delete()`](struct.LdapConn.html#method.delete).
    pub fn delete(&self, dn: &str) -> Box<Future<Item = LdapResult, Error = io::Error> + Send> {
        let req = Tag::OctetString(OctetString {
            id: 10,
            class: TagClass::Application,
            inner: Vec::from(dn.as_bytes()),
        });

        let fut = self
            .call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|response| {
                let (mut result, controls) = (LdapResult::from(response.0), response.1);
                result.ctrls = controls;
                Ok(result)
            });

        Box::new(fut)
    }
}

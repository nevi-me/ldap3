use std::io;

use lber::common::TagClass;
use lber::structures::{Integer, Tag};

use futures::{future, Future};
use tokio_service::Service;

use ldap::{bundle, next_req_controls, Ldap, LdapOp};
use protocol::LdapRequestId;

impl Ldap {
    #[doc(hidden)]
    /// Abandon the request identified by `msgid`. Since this requires knowing the
    /// `msgid` of an operation, it currently works only for streaming searches,
    /// invoked via methods on structures representing those searches. See
    /// [`EntryStream::abandon()`](struct.EntryStream.html#method.abandon) and
    /// [`SearchStream::get_abandon_channel()`](struct.SearchStream.html#method.get_abandon_channel).
    pub fn abandon(
        &self,
        msgid: LdapRequestId,
    ) -> Box<Future<Item = (), Error = io::Error> + Send> {
        let bundle = bundle(self);
        if !bundle
            .clone()
            .into_inner()
            .unwrap()
            .id_map
            .contains_key(&msgid)
        {
            return Box::new(future::err(io::Error::new(
                io::ErrorKind::Other,
                format!("msgid {} not an active operation", msgid),
            )));
        }
        let req = Tag::Integer(Integer {
            id: 16,
            class: TagClass::Application,
            inner: msgid as i64,
        });

        let fut = self
            .call(LdapOp::Solo(req, next_req_controls(self)))
            .and_then(|_x| Ok(()));

        Box::new(fut)
    }
}

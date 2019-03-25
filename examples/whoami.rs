// extern crate ldap3;

// use std::error::Error;

// use ldap3::LdapConn;
// use ldap3::exop::{WhoAmI, WhoAmIResp};

// fn main() {
//     match do_whoami() {
//         Ok(authzid) => println!("{}", authzid),
//         Err(e) => println!("{:?}", e),
//     }
// }

// fn do_whoami() -> Result<String, Box<Error>> {
//     let ldap = LdapConn::new("ldap://localhost:2389")?;
//     ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?.success()?;
//     let (exop, _res) = ldap.extended(WhoAmI)?.success()?;
//     let whoami: WhoAmIResp = exop.parse();
//     Ok(whoami.authzid)
// }

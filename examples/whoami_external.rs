extern crate ldap3;

use std::error::Error;

use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::LdapConn;

fn main() {
  match do_whoami() {
    Ok(authzid) => println!("{}", authzid),
    Err(e) => println!("{:?}", e),
  }
}

fn do_whoami() -> Result<String, Box<Error>> {
  let ldap = LdapConn::new("ldapi://ldapi")?;
  ldap.sasl_external_bind()?.success()?;
  let (exop, _res) = ldap.extended(WhoAmI)?.success()?;
  let whoami: WhoAmIResp = exop.parse();
  Ok(whoami.authzid)
}

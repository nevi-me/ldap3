extern crate ldap3;

use std::error::Error;

use ldap3::{LdapConn, Scope, SearchEntry, SearchOptions};

fn main() {
  match do_search() {
    Ok(_) => (),
    Err(e) => println!("{:?}", e),
  }
}

fn do_search() -> Result<(), Box<Error>> {
  let ldap = LdapConn::new("ldap://localhost:2389")?;
  let (rs, res) = ldap
    .with_search_options(SearchOptions::new().sizelimit(1))
    .search(
      "ou=People,dc=example,dc=org",
      Scope::Subtree,
      "objectClass=inetOrgPerson",
      vec!["uid"],
    )?
    .success()?;
  println!("Result: {:?}", res);
  for entry in rs {
    println!("{:?}", SearchEntry::construct(entry));
  }
  Ok(())
}

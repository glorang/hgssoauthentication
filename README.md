# Mercurial Kerberos SSO Authentication plugin

This plugin is a fork of Dominik Ruf's Mercurial Kerberos SSO plugin. 

It has been enhanced to: 

- Supports Python 3 / Mercurial 5 (and up) on Windows/Linux/macOS
- Supports keytab authentication on Linux & macOS

# Requirements

- Your machine must be domain joined
- Linux: install packages python3-kerberos and python3-urllib3 

# Installation

Add following entry to your .hgrc/mercurial.ini (adjust path as required):

```
[extensions]
hgext.kerberos=~/hgssoauthentication.py
```

# Keytab usage

This is only supported on Linux and macOS. Especially useful for non-Kerberized machines or service accounts.
Note that changing the domain password of a user will invalidate the keytab and you need to re-execute this procedure

- On a Linux machine enter ktuil (package krb5-user)
- Generate keytab
```
ktutil:  add_entry -password -p username@DOMAIN.COM -k 1 -f
Password for username@DOMAIN.COM:
```
- Write keytab
```
ktutil:  write_kt username.keytab
```
- Exit ktutil by pressing `CTRL + D`
- Update `~/.hgrc` and add `[krb]` section 
```
[extensions]
hgext.kerberos=~/hgssoauthentication.py

[krb]
keytab = ~/username.keytab
principal = username@DOMAIN.COM
```

# Known issues

- In rare cases keytabs do not work on macOS 
- When using Python 3 / Mercurial 5 (and up) following exception is thrown : "AbstractDigestAuthHandler does not support the following scheme: 'Negotiate'" - See [#6792](https://bz.mercurial-scm.org/show_bug.cgi?id=6792) and [#6343](https://bz.mercurial-scm.org/show_bug.cgi?id=6343)

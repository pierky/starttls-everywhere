# STARTTLS Everywhere - Usage

The STARTTLS Everywhere project offers the following tools:

* **DefsParser.py**, to parse and validate definitions files and to display resultant policy for a given mail domain.
* **MTAConfigGenerator.py**, which translates policies into MTA-specific directives and fixes (upon user's confirmation) MTA general configuration in order to allow STARTTLS enforcing.
* **MTALogWatcher.py** (NOT IMPLEMENTED YET), to analyze MTAs' logs and report how many delivery failures are due to STARTTLS enforcing policies.

## Configuration

By default, STARTTLS-Everywhere programs load the configuration from **/etc/starttls-everywhere/starttls-everywhere.cfg**. Here some generic settings and some MTA-specific parameters can be configured. Even if default parameter values may be suitable for most deployments it's safe to have a look at that file. The configuration path can also be specified using the **--cfg** command line argument.

## Policy definitions validation

The **DefsParser.py** script allows to parse a policy definitions file and to validate it:

```
$ ./DefsParser.py distrib/example_policy.json
Validation OK
```

It can be used to show the resultant policy for a specific mail domain too:

```
$ ./DefsParser.py distrib/example_policy.json -j eff.org
Validation OK
{
  "comment": "Leaf certificate validation through fingerprint",
  "ee-tlsa": [
    {
      "entity": "certificate",
      "data": "8af8c314ff7e343ae4bf0bf16c7cbe3856840d1172073ed9c7d8f002fd3081cf",
      "data_format": "hex",
      "hash_alg": "sha256"
    }
  ],
  "min-tls-version": "TLSv1.2",
  "certificate-matching": "EE"
}
```

## MTAs configuration generator

**MTAConfigGenerator.py** is the program used to manage MTAs configuration and STARTTLS-enforcing policies.
The program can be used in two ways:

1. to parse a policy definitions file and translate it into MTA-specific configuration;
2. to fix the current MTA's configuration in order to ensure that it's compatible with STARTTLS-enforcing policies.

Both methods do not modify the current MTA's configuration unless a specific argument is supplied by command line; instead, they only display the changes that are needed.

1. Display Postfix's general configuration changes needed for STARTTLS-enforcing policies:

  ```
  $ sudo ./MTAConfigGenerator.py distrib/example_policy.json -m Postfix --fix
  MTA general configuration changes are needed.
  Differences between current /etc/postfix/main.cf and the new configuration follow:

          diff -y /tmp/tmpBdvyE_ /etc/postfix/main.cf


  # See /usr/share/postfix/main.cf.dist for a commented, more c   # See /usr/share/postfix/main.cf.dist for a commented, more c


  # Debian specific:  Specifying a file name will cause the fir   # Debian specific:  Specifying a file name will cause the fir
  # line of that file to be used as the name.  The Debian defau   # line of that file to be used as the name.  The Debian defau
  # is /etc/mailname.                                             # is /etc/mailname.
  #myorigin = /etc/mailname                                       #myorigin = /etc/mailname

  [cut]

                                                                <
                                                                <
  #                                                             <
  # New config lines added by STARTTLS Everywhere               <
  #                                                             <
  smtp_tls_security_level=may                                   <
  smtp_tls_fingerprint_digest=sha256                            <
  smtp_tls_policy_maps=btree:/etc/postfix/starttls-everywhere   <
  smtp_tls_CApath=/etc/ssl/certs/                               <

  MTA general configuration changes NOT saved: use -s | --save to save them.
  ```

  Also save them:

  ```
  $ sudo ./MTAConfigGenerator.py distrib/example_policy.json -m Postfix --fix --save
  MTA general configuration changes saved.
  Ensure your MTA is using the new configuration; reload it if needed.
  ```

2. Display Postfix's specific configuration for policies:

  ```
  $ sudo ./MTAConfigGenerator.py distrib/example_policy.json -m Postfix
  # Leaf certificate validation through fingerprint
  eff.org fingerprint match=8a:f8:c3:14:ff:7e:34:3a:e4:bf:0b:f1:6c:7c:be:38:56:84:0d:11:72:07:3e:d9:c7:d8:f0:02:fd:30:81:cf protocols=TLSv1.2
  ```

  Save the policies into the Postfix's smtp_tls_policy_maps table:

  ```
  $ sudo ./MTAConfigGenerator.py distrib/example_policy.json -m Postfix --save
  Policy definitions updated and used by MTA!
  ```

#### Not implemented policies

If an MTA does not implement a feature used by a policy, the MTA config generator stops its execution and displays an error in order to avoid a partial compliance between the MTA's configuration and the policy itself. To skip those policies that use unimplemented features the program can be run with the **--ignore [error_type [error_type ...]]** argument. For example, Postfix can't handle policies with the **log-only = true** property:

```
$ sudo ./MTAConfigGenerator.py distrib/example_not_implemented.json -m Postfix
Not implemented: log-only = True (example.org)
Use the '--ignore log-only' argument to ignore those policies that use this unimplemented feature.
$ sudo ./MTAConfigGenerator.py distrib/example_not_implemented.json -m Postfix --ignore log-only
# Leaf certificate validation through fingerprint
eff.org fingerprint match=8a:f8:c3:14:ff:7e:34:3a:e4:bf:0b:f1:6c:7c:be:38:56:84:0d:11:72:07:3e:d9:c7:d8:f0:02:fd:30:81:cf protocols=TLSv1.2

Policy definitions NOT updated: use -s | --save to save them.
```

A list of exceptions that can be skipped can be obtained with the **--show-ignore-list** argument:

```
$ sudo ./MTAConfigGenerator.py distrib/example_not_implemented.json -m Postfix --show-ignore-list
List of exceptions that can be ignored by Postfix config generator:
 - ta-tlsa: skip policies that require Trust Anchor validation but that provide certificate's or pubkey's digest only
 - log-only: skip policies where log-only = True
```

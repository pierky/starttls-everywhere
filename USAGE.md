# STARTTLS Everywhere - Usage

The STARTTLS Everywhere project offers the following tools:

* **DefsParser.py**, to parse and validate definitions files and to display resultant policy for a given mail domain.
* **MTAConfigGenerator.py**, which translates policies into MTA-specific directives and fixes (upon user's confirmation) MTA general configuration in order to allow STARTTLS enforcing.
* **MTALogWatcher.py**, to analyze MTAs' logs and report how many delivery failures are due to STARTTLS enforcing policies.
* **GuessSTARTTLSPolicies.py**, to *guess* a policy for recipient domains on the basis of a set of attributes shared among MX hosts (WARNING: read its disclaimer - use it at your own risk).

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

## MTAs log watcher and failure reporting

The **MTALogWatcher.py** program allows to parse and analyze MTAs' log files in order to find issues due to STARTTLS-Everywhere policies enforcing.

It can be run to parse whole log files or to use an incremental reading method that allows to resume parsing where the last execution stopped, useful to schedule it in a cron job.

Multiple output types can be chosen:

* the **-o warnings** (default) allows to display mail domains that have been found to exceed the configured delivery failure threshold:

  ```
  $ sudo ./MTALogWatcher.py -m Postfix /var/log/mail.log -o warnings
  Displaying successful/failed delivery attempts for domains with an high failure rate (0.1%)

  bad-starttls.example.com: 143 delivery attempts, 56 succeeded, 87 failed, 60.84% failure rate - WARNING
  ```

  It also causes MTALogWatcher to log delivery errors due to STARTTLS-Everywhere policies and (optionally) to notify them via email (log_smtp_* configuration parameters).
  A report for mail domains that encountered delivery issues is also saved for further analysis (logwatcher_reports_* configuration parameters).

* the **-o domains** is similar to the **warnings** output type but shows results for every analysed domain and avoid errors logging;

* two of them (**-o matched-lines** and **-o unmatched-lines**) are mostly useful for debug purposes to evaluate the efficacy of the regular expressions used to match relevant log lines, by printing the log lines that have been taken into account for analysis and those that have been ignored.

## GuessSTARTTLSPolicies

This script consumes a list of recipient mail domains and, for each one of them, it builds a TLS policy on the basis of the response of its MX hostnames.
A set of attributes that are common to all the MX hosts is built, including TLS version, Trust Anchors, End Entity certificates, their public keys and names (CN + SANs).
Decisions are made on the basis of the set of common attributes, with the following priority list:
* Trust Anchors
* EE certificates' public key
* EE certificates (exact matching)
* any valid certificate

>WARNING: the policy herein built is based on a set of common
>features found among the current layout and configuration of the MX hostnames
>associated to input mail domains. There is no warranty that the current
>settings will be kept by mail servers' owners in the future nor that these
>settings are the correct ones that really identify the recipient domain's mail
>servers. A bad policy could result in messages delivery failures.

**USE POLICIES BUILT BY THIS SCRIPT AT YOUR OWN RISK.**

For more details:

```
$ ./GuessSTARTTLSPolicies.py -h
```

# STARTTLS Everywhere - Policy definitions format

## JSON 

Current version is 0.x, that is it's still a draft.

### Policy definitions
```
{
  // Canonical URL https://eff.org/starttls-everywhere/config
  // redirects to latest version

  // "version": "X[.Y[.Z]]"
  // Changes that are not backward-compatible or that are mandatory but not
  // implemented in previous versions need a new major.
  "version": "0.1",

  // "timestamp": "[YYYY]-[MM]-[DD]T[hh]:[mm]:[ss]" (UTC)
  // "timestamp": 1401414363, also acceptable (UTC)
  "timestamp": "2014-06-06T14:30:16",

  "author": "Electronic Frontier Foundation https://eff.org",

  // "expires": "[YYYY]-[MM]-[DD]T[hh]:[mm]:[ss]" (UTC)
  // "expires": 1401414363, also acceptable (UTC related)
  "expires": "2014-06-06T14:30:16",

  "global-policies": {
    "global-policy1": {
      <Policy>,

      }
    },
    "global-policyN": { ... }
  },

  "tls-policies": {
    // Match on mail domain (the part after @)
    "domain1.tld": {
      // For certificate names matching purposes, the domain is used to
      // verbatim match the name on the EE certificate.
      // "domain1.tld" only matches leaf certificates with "domain1.tld"
      // in SubjectAlternativeName or in CommonName; "sub1.domain1.tld"
      // does not match (unless otherwise specified in "allowed-cert-names").

      // Optional.
      // If specified, the current policy will inherit settings from the
      // one in the global-policies. Local attributes override those
      // inherited from the global policy; setting an attribute to null
      // will remove it from the list of inherited settings.
      "from-global": "global-policy1",

      <Policy>
      }
    },
    "domainN.tld": { ... }
  }
}
```
### Policy
```
{
  // Approch similar to "SMTP security via opportunistic DANE TLS".
  // https://tools.ietf.org/html/draft-ietf-dane-smtp-with-dane

  // Optional, used at MTA Config Generator's discretion to add a comment.
  "comment": "string",

  // Optional - default: none (no certificate matching applied).
  "certificate-matching": "{ valid, TA, EE }",

  // Optional - default: False (message delivery deferred if STARTTLS unsupported
  //                            or bad cert).
  // If True, a warning must be logged by MTAs but message delivery must not be
  // deferred.
  "log-only": boolean,

  // Optional.
  "min-tls-version": "{ TLSv1, TLSv1.1, TLSv1.2, TLSv1.3 }",

  // Optional, required if "certificate-matching" == "EE".
  // List of TLSAs that describe allowed EE certificates.
  // If MTA config generators can't implement any of the TLSA
  //  listed here they must report failure.
  "ee-tlsa": [ TLSA ],

  // Optional, required if "certificate-matching" == "TA".
  // List of TLSAs that describe allowed Trust Anchors.
  // If MTA config generators can't implement any of the TLSA
  //      listed here they must report failure.
  "ta-tlsa": [ TLSA ]

  // Optional, used only when "certificate-matching" in [ "valid", "TA" ]
  // List of allowed names expected to be found in server's leaf certificates.
  // Each name must be a valid FQDN, optionally with a "." prefix in order to
  // match any FQDN ending with the given name.
  // Example: .domain.tld matches sub1.domain.tld and also sub2.sub1.domain.tld).
  "allowed-cert-names": [ "sub1.domain.tld", "subN.domain.tld", ".domain.tld" ]
}
```

#### TLSA
```
{
  // Similar to RFC6698 "Selector Field"
  // https://tools.ietf.org/html/rfc6698#section-2.1.1
  "entity": "{ pubkey, certificate }",

  // Similar to RFC6698 "Matching Type Field"
  // https://tools.ietf.org/html/rfc6698#section-2.1.3
  //
  // Optional: if missing, the TLSA describes the full entity, like the TLSA Matching
  //           Types = Full(0), and not its hash.
  "hash_alg": "{ sha1, sha256, sha512 }",

  // See "data" for more details.
  "data_format": "{ hex, b64 }",

  // Similar to RFC6698 "Certificate Association Data Field"
  // https://tools.ietf.org/html/rfc6698#section-2.1.4
  // Depends on "data_format":
  //
  //  "hex": string of hexadecimal characters for the binary raw data of
  //         what is represented by "entity" and "hash_alg".
  //
  //         Example: "ab12cd34...".
  //
  //  "b64": base64 encoded version for the binary raw data of what is represented
  //         by "entity" and "hash_alg" (without any "-----BEGIN xxx-----").
  //
  //         Example: "MIIHgzCCA2ugAwIBAgIC..."
  "data": "string"
}
```

## Main structures

### Policies

A **policy** is a list of settings that describes how the MTA must treat message delivery for a particular recipient **mail domain** (the part of an address after the "@").

### tls-policies field

The *tls-policies* field maps from **mail domains** onto a list of properties for that domain (the **policy**). Matching of mail domains is on an exact-match basis, not a subdomain basis. For instance, eff.org would be listed separately from lists.eff.org in the *tls-policies* section.

Implicitly each **mail domain** listed has a property `require-tls: true`. **Mail domain** that do not support TLS will not be listed.

At this time it's not possible to use different policies for different recipient SMTP servers within the same **mail domain**.

### global-policies field

The *global-policies* field is an optional list of generic policies that **mail domains** can inherit settings from. **Global policies** may be useful to group many **mail domains** into a common set of properties, for example to describe a mail hosting service where many **mail domains** use the same mail provider's infrastructure.

Any local properties override those inherited from a global policy; inherited properties can be removed by setting local property to **null**. In the following example, every subX.example.org domain has the `from-global = "Parent"` property:

```
Resultant policy:                                        Original JSON policy definitions file
{                                                        {
  "author": "Electronic Frontier Foundation https://eff.o  "author": "Electronic Frontier Foundation https://eff.org",
  "timestamp": "2015-05-29T18:25:43",                      "timestamp": "2015-05-29T18:25:43",
  "expires": "2016-05-29T18:25:43",                        "expires": "2016-05-29T18:25:43",
  "global-policies": {                                     "global-policies": {
    "Parent": {                                              "Parent": {
      "allowed-cert-names": [                                  "allowed-cert-names": [
        ".example.org"                                           ".example.org"
      ],                                                       ],
      "min-tls-version": "TLSv1"                               "min-tls-version": "TLSv1"
    }                                                        }
  },                                                       },
  "version": "0.1",                                        "version": "0.1",
  "tls-policies": {                                        "tls-policies": {
    "sub1.example.org": {                                    "sub1.example.org": {
      "comment": "Fully inherited from Parent",                "comment": "Fully inherited from Parent",
      "allowed-cert-names": [
        ".example.org"
      ],
      "min-tls-version": "TLSv1"
                                                               "from-global": "Parent"
    },                                                       },
    "sub2.example.org": {                                    "sub2.example.org": {
      "comment": "Add log-only = true",                        "comment": "Add log-only = true",
      "allowed-cert-names": [
        ".example.org"
      ],
      "min-tls-version": "TLSv1",
      "log-only": true                                         "log-only": true,
                                                               "from-global": "Parent"
    },                                                       },
    "sub3.example.org": {                                    "sub3.example.org": {
      "comment": "Change min-tls-version",                     "comment": "Change min-tls-version",
      "allowed-cert-names": [
        ".example.org"
      ],
      "min-tls-version": "TLSv1.2"                             "min-tls-version": "TLSv1.2",
                                                               "from-global": "Parent"
    },                                                       },
    "sub4.example.org": {                                    "sub4.example.org": {
      "comment": "Remove min-tls-version",                     "comment": "Remove min-tls-version",
      "allowed-cert-names": [
        ".example.org"
      ]
                                                               "min-tls-version": null,
                                                               "from-global": "Parent"
    }                                                        }
  }                                                        }
}                                                        }
```
## Policy settings

### certificate-matching

An approch similar to "SMTP security via opportunistic DANE TLS" (https://tools.ietf.org/html/draft-ietf-dane-smtp-with-dane) is used here.

The optional *certificate-matching* property rules the main logic and disposes how recipient servers' EE (end-entity) certificates are validated:

* missing: STARTTLS is enforced but EE certificates are not validated;
* **valid**: STARTTLS is enforced and EE (end-entity) certificates are validated against the local Certification Authorities trust store;
  * the EE certificates must be valid (not expired nor revoked) and signed by a trusted Certification Authority;
  * certificate name matching applies (see below);
* **TA**: STARTTLS is enforced and EE certificates are validated on a Trust Anchor (TA) basis;
  * the EE certificates must chain up to at least one of the issuing authorities defined in *ta-tlsa* field;
  * certificate name matching applies (see below);
* **EE**: STARTTLS is enforced and EE certificates are validated on the basis of their fingerprints;
  * the EE certificates must match at least one of the certificates defined in *ee-tlsa* field;
  * certificate name matching does not apply;

Since at this time it's not possible to use different policies for different recipient SMTP servers, a common certificate matching criteria must be chosen to match the configuration of every recipient SMTP server within the same **mail domain**. For example, if mx1.example.com uses a self-signed certificate and mx2.example.com uses a certificate from a public trusted CA then the `certificate-matching = "valid"` option can't be used, otherwise the mx1.example.com certificate would never be validated. In this case, the **EE** option with EE certificates TLSAs can be used.

### ta-tlsa and ee-tlsa fields

TLSAs describes entities (full certificates or public keys) by using a digest or their full binary representation (encoded in hex string or base64).

Each element of  *ta-tlsa* and *ee-tlsa* field must contain an *entity* field which describes the entity's type: certificate or public key.
If the *hash_alg* is given, the TLSA is meant to describe the entity by means of its digest.
The *data_format* and *data* fields contain the representation of what is described by the TLSA.

Some useful commands to obtain certificates' and public keys' info:

* Full certificate, **b64** *data_format*:
  ```
  openssl x509 -in cert.pem -outform der | base64 -w 0
  ```

* Full public key, **b64** *data_format*:
  ```
  openssl x509 -in cert.pem -noout -pubkey | openssl pkey -pubin -outform der | base64 -w 0
  ```

* Certificate SHA-256 digest, **hex** *data_format*:
  ```
  openssl x509 -in cert.pem -outform der | openssl dgst -sha256
  ```

* Public key SHA-256 digest, **hex** *data_format*:
  ```
  openssl x509 -in cert.pem -noout -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256
  ```

### Certificate name matching

Certificate name matching applies whenever **valid** or **TA** *certificate-matching* are given and is used to match the names in the EE certificates provided by recipient SMTP servers.
In order to be considered valid a certificate must provide a name that fully match the **mail domain** or one of the FQDNs in the *allowed-cert-names* field. The *allowed-cert-names* list can include names starting with "." (a dot) in order to match any name ending with the given label (example: .domain.tld matches sub1.domain.tld and also sub2.sub1.domain.tld).

### Other settings

If `log-only = true`, the generated configs will not stop mail delivery on policy failures, but will produce logging information.

If the *min-tls-version* property is present, sending mail to domains under this policy should fail if the sending MTA cannot negotiate a TLS version equal to or greater than the listed version.

## MTA compatibility

| MTA          | certificate-matching                | log-only | min-tls-version | allowed-cert-names |
|:-------------|:------------------------------------|:--------:|:---------------:|:-------------------|
|Postfix       | none, **valid**, **TA** (1), **EE** | no       | yes             | FQDN and "."-domain|

1) for TA-based validation only full entities are supported (*hash_alg* not present).

## Policy definitions expiration and validation

The *timestamp* field is an integer number of epoch seconds (UTC). When retrieving a fresh configuration file, config-generator should validate that the timestamp is greater than or equal to the version number of the file it already has.

There is no inline signature field. The configuration file should be distributed with authentication using an offline signing key.

Option 1: Plain JSON distributed with a signature using gpg --clearsign. Config-generator should validate the signature against a known GPG public key before extracting. The public key is part of the permanent system configuration, like the fetch URL.

Option 2: Git is a revision control system built on top of an authenticated, history-preserving file system.  Let's use it as an authenticated, history preserving file system: valid versions of recipient policy files may be fetched and verified via signed git tags.  [Here's an example shell recipe to do this.](https://gist.github.com/jsha/6230206e89759cc6e00d)

Config-generator should attempt to fetch the configuration file daily and transform it into MTA configs. If there is a retrieval failure, and the cached configuration file has an 'expires' time past the current date, an alert should be raised to the system operator and all existing configs from config-generator should be removed, reverting the MTA configuration to use opportunistic TLS for all domains.

# STARTTLS Everywhere

## Authors

Jacob Hoffman-Andrews <jsha@eff.org>, Peter Eckersley <pde@eff.org>, Pier Carlo Chiodi <pierky@pierky.com>

## Mailing List

starttls-everywhere@eff.org, https://lists.eff.org/mailman/listinfo/starttls-everywhere

## Background

Most email transferred between SMTP servers (aka MTAs) is transmitted in the clear and trivially interceptable. Encryption of SMTP traffic is possible using the STARTTLS mechanism, which encrypts traffic but is vulnerable to a trivial downgrade attack.

To illustrate an easy version of this attack, suppose a network-based attacker Mallory notices that Alice has just uploaded message to her mail server. Mallory can inject a TCP reset (RST) packet during the mail server's next TLS negotiation with another mail server. Nearly all mail servers that implement STARTTLS do so in opportunistic mode, which means that they will retry without encryption if there is any problem with a TLS connection. So Alice's message will be transmitted in the clear.

Opportunistic TLS in SMTP also extends to certificate validation. Mail servers commonly provide self-signed certificates or certificates with non-validatable hostnames, and senders commonly accept these. This means that if we say 'require TLS for this mail domain,' the domain may still be vulnerable to a man-in-the-middle using any key and certificate chosen by the attacker.

Even if senders require a valid certificate that matches the hostname of a mail host, a DNS MITM is still possible. The sender, to find the correct target hostname, queries DNS for MX records on the recipient domain. Absent DNSSEC, the response can be spoofed to provide the attacker's hostname, for which the attacker holds a valid certificate.

STARTTLS by itself thwarts purely passive eavesdroppers. However, as currently deployed, it allows either bulk or semi-targeted attacks that are very unlikely to be detected. We would like to deploy both detection and prevention for such semi-targeted attacks.

## Goals

*   Prevent RST attacks from revealing email contents in transit between major MTAs that support STARTTLS.
*   Prevent MITM attacks at the DNS, SMTP, TLS, or other layers from revealing same.
*   Zero or minimal decrease to deliverability rates unless network attacks are actually occurring

## Non-goals

*   Prevent fully-targeted exploits of vulnerabilities on endpoints or on mail hosts.
*   Refuse delivery on the recipient side if sender does not negotiate TLS (this may be a future project).
*   Develop a fully-decentralized solution.
*   Initially we are not engineering to scale to all mail domains on the Internet, though we believe this design can be scaled as required if large numbers of domains publish policies to it.

## Motivating examples

*   [Unnammed mobile broadband provider overwrites STARTTLS flag and commands to
    prevent negotiating an encrypted connection]
    (https://www.techdirt.com/articles/20141012/06344928801/revealed-isps-already-violating-net-neutrality-to-block-encryption-make-everyone-less-safe-online.shtml)
*   [Unknown party removes STARTTLS flag from all SMTP connections leaving
    Thailand](http://www.telecomasia.net/content/google-yahoo-smtp-email-severs-hit-thailand)

## Threat model

Attacker has control of routers on the path between two MTAs of interest. Attacker cannot or will not issue valid certificates for arbitrary names. Attacker cannot or will not attack endpoints. We are trying to protect confidentiality and integrity of email transmitted over SMTP between MTAs.

## Alternatives

Our goals can also be accomplished through use of [DNSSEC and DANE](http://tools.ietf.org/html/draft-ietf-dane-smtp-with-dane), which is certainly a more scalable solution. However, operators have been very slow to roll out DNSSEC supprt. We feel there is value in deploying an intermediate solution that does not rely on DNSSEC. This will improve the email security situation more quickly. It will also provide operational experience with authenticated SMTP over TLS that will make eventual rollout of a DANE solution easier.

## Detailed design

Senders need to know which target hosts are known to support STARTTLS, and how to authenticate them. Since the network cannot be trusted to provide this information, it must be communicated securely out-of-band. We will provide:

  (a) a configuration file format to convey STARTTLS support for recipient domains,

  (b) Python code (config-generator) to transform (a) into configuration files for popular MTAs, and

  (c) a method to create and securely distribute files of type (a) for major email domains that agree to be included, plus any other domains that proactively request to be included.

## File Format

Please refer to [POLICY_DEFS_FORMAT.md](POLICY_DEFS_FORMAT.md) for the format hereinafter described.

A user of this file format may choose to accept multiple files. For instance, the EFF might provide an overall configuration covering major mail providers, and another organization might produce an overlay for mail providers in a specific country. If so, they override each other on a per-domain basis.

The *version* field contains the version of the format used for the file. Every time that a new feature is introduced in the file format and it's not backward-compatible with the previous version (for example, it involves different behaviours from the default ones used if that feature would not be implemented) the major will be incremented by 1. MTAs config generator must reject files that have a major version greater than the one they have been released for.

## Pinning and hostname verification

Like Chrome (and soon Firefox) we want to encourage pinning to a trusted root or intermediate (`certificate-matching = "TA"`) rather than a leaf cert, to minimize spurious pinning failures when hosts rotate keys.

The other option is to automatically pin leaf certs as observed in the wild.  This would be one solution to the hostname verification and self-signed certificate problem. However, it is a non-starter. Even if we expect mail operators to auto-update configuration on a daily basis, this approach cannot add new certs until they are observed in the wild. That means that any time an operator rotates keys on a mail server, there would be a significant window of time in which the new keys would be rejected.

## Creating policy definitions

We have three options for creating the configuration file:

1.  Ask mail operators to submit policies for their domains which we incorporate.
2.  Manually curate a set of policies for the top N mail domains.
3.  Programmatically create a set of policies by connecting to the top N mail domains.

For option (1), there's a bootstrapping problem: No one will opt in until it's useful; It won't be useful until people opt in. Option (1) does have the advantage that it's the only good way to get pinning directives.

For option (3) we'd be likely to pull in bad policies that could result in failed delivery.

We'll initially launch a demo using option (2), do some initial deployments to prove viability and delivery rate impact, and then start reaching out to operators to do option (1).

## Distribution

The configuration file will be provided at a long-term maintained URL. It will be signed using a key held offline on an airgapped machine or smartcard.

Since recipient mail servers may abruptly stop supporting TLS, we will request that mail operators set up auto-updating of the configuration file, with signature verification. This allows us to minimize the delivery impact of such events. However, config-generator should not auto-update its own code, since that would amount to auto-deployment of third party code, which some operators may not wish to do.

We may choose to implement a form of immutable log along the lines of certificate transparency. This would be appealing if we chose to use this mechanism to distribute expected leaf keys as a primary authentication mechanism, but as described in "Pinning and hostname verification," that's not a viable option. Instead we will rely on the CA ecosystem to do primary authentication, so an immutable log for this system is probably overkill, engineering-wise.

## Python code

Config-generator should parse input JSON and produce output configs for various mail servers. It should not be possible for any input JSON to cause arbitrary code execution or even any MTA config directives beyond the ones that specifically impact the decision to deliver or bounce based on TLS support. For instance, it must not be possible for config-generator to output a directive to forward mail from one domain to another. Config-generator will have the option to directly pull the latest config from a URL, or from a file on local disk distributed regularly from another system that has outside network access.

Config-generator will be manually updated by mail operators.

At this time only the Postfix MTA config-generator is implemented.

Please refer to [INSTALLATION.md](INSTALLATION.md) and [USAGE.md](USAGE.md) for further details.

## Testing

We will create a reproducible test configuration that can be run locally and exercises each of the major cases: Enforce mode vs log mode; Enforced TLS negotiation and enforced valid certificates.

Additionally, for ongoing monitoring of third-party deployments, we will create a canary mail domain that intentionally fails one of the tests but is included in the configuration file. For instance, starttls-canary.org would be listed in the configuration as requiring STARTTLS, but would not actually offer STARTTLS. Each time a mail operator commits to configuring STARTTLS Everywhere, we would request an account on their email domain from which to send automated daily email to starttls-canary.org. We should expect bounces. If such mail is successfully delivered to starttls-canary.org, that would indicate a configuration failure on the sending host, and we would manually notify the operator.

## Failure reporting

For the mail operator deploying STARTTLS Everywhere, we will provide log analysis scripts that can be used out-of-the-box to monitor how many delivery failures or would-be failures are due to STARTTLS Everywhere policies. These would be designed to run in a cron job and send notices only when STARTTLS Everywhere-related failures exceed 0.1% for any given recipient domains. For very high-volume mail operators, it would likely be necessary to adapt the analysis scripts to their own logging and analysis infrastructure.

For recipient domains who are listed in the STARTTLS Everywhere configuration, we would provide a configuration field to specify an email address or HTTPS URL to which that sender domains could send failure information. This would provide a mechanism for recipient domains to identify problems with their TLS deployment and fix them. The reported information should not contain any personal information, including email addresses.  Example fields for failure reports: timestamps at minute granularity, target MX hostname, resolved MX IP address, failure type, certificate. Since failures are likely to come in batches, the error sending mechanism should batch them up and summarize as necessary to avoid flooding the recipient.

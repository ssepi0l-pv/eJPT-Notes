# Table of Contents

- [Assessment methodologies](#1)
  - [Cybersecurity Basics](#1.1)
    - [CIA Triad](#1.1.1)
    - [Defense in-depth](#1.1.2)
    - [Business needs](#1.1.3)
  - [Compliance](#1.2)
  - [Frameworks and maturity](#1.3)
  - [Auditing](#1.4)
- [Practices](#2)
  - [SCAP Scan and Stigviewer](#2.1)
  - [Nmap](#2.2)
  - [Nessus](2.3)

<a id=1></a>
# Assessment methodologies

<a id=1.1></a>
## Cybersecurity Basics

What is cybersecurity? Cybersecurity is the protection of computer systems and networks from information disclosure, theft,
damage to the hardware, software or the information that it contains, as well as the disruption of the services that they
provide.

We protect:

- PII (Personally Identifiable Information)
- Healthcare information
- Financial data
- Intellectual property
- Business secrets
- Business Operations

We protect them from:

- Criminals.
- Competitors.
- Insider Threats.
- Malicious Actors.

<a id=1.1.1></a>
### CIA Triad

The CIA triad is composed of three parts:

1. Confidentiality: only authorized individuals or groups have access to a determined piece of information. *For your eyes only.*
2. Integrity: information in transit is received as it was sent. No change is done during transit or in rest. Integrity is kept. *Only authorized changes, please.*
3. Availability: a service is available whenever needed. *I have a job to do here.*

<a id=1.1.2></a>
### Defense in-depth.

Defense in-depth is a concept that describes the added protection to a system or a piece of information. This goes beyond only technological controls.
We don't just have the latest and most secure updates in a system, but we also keep that system locked from unauthorized physical access. We build a castle
to protect our most important assets. It's a system of layers. Many barriers exist to protect a system or a piece of information. For example:

1. Perhaps an attacker can bypass our firewall. Good, we have our systems in a different network. Our net is no plane.
2. Perhaps the attacker gets inside a server. But the server is a decoy, we use cyber-deception to trick him. We're safe.
3. Perhaps the attacker can laterally move to another networks. Fine. Our most important systems are air-gapped, inaccessible from
any network. The attacker might break a laptop or a printer, but our most important assets are left untouched.

<a id=1.1.3></a>
### Business needs

The systems will be as secure as the business needs them to be. For example: an enterprise that doesn't collect user data and/or financial information
does not need to be PCI DSS compliant. 

Maybe it's a small enterprise. It probably won't have the need nor the resources to buy the latest and greatest router, or the top NGFW that Fortinet
launched last week. It might be okay with a pfSense and nothing more. It'll depend on the case, the business need.

<a id=1.2></a>
## Compliance

A lot of what we comply with is related to risk management, certain country laws and regulations, partner expectations and more. As described above,
if we don't make store transaction information or if we aren't a banking institution, we don't have to comply with PCI DSS. But maybe our country 
has a regulation in which all IT companies -- for example -- have to comply with ISO 27.001. And maybe we also do store PII in AWS, so we also have to comply
with ISO 27.018.

<a id=1.3></a>
## Frameworks and maturity

<a id=1.4></a>
## Auditing

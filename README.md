# ASV (Amtliche Schulverwaltung Bayern): Pre-Auth Authentication Bypass and Java Deserialization

**Reporter:** Jürgen Bilberger, Cybersecurity Center (CSC), Landeshauptstadt München
**Coordination:** LSI Bayern (Bayern-CERT)
**Published:** 2026-11-11
**Status:** Fixed in ASV 26.2 (2026-06-30)

| ID | Vulnerability | CWE | CVSS 3.1 |
|---|---|---|---|
| CVE-pending (V1) | Pre-auth SysAdmin authentication bypass | CWE-288 | 9.8 |
| CVE-pending (V2) | Pre-auth Java deserialization without class allowlist | CWE-502 | 8.1 |

Both issues are in the server-side Hessian-RPC service of ASV, the school
administration software used at Bavarian schools. Both were reachable over
the network without authentication.

**Affected:** ASV Bayern before 26.2. The sister products ASV-BW
(Baden-Württemberg) and edoosys.RLP (Rhineland-Palatinate) share the code
base and received fixed releases on 2026-07-21. I tested only an authorized
ASV Bayern test instance operated by Landeshauptstadt München.

The fixes shipped silently in 26.2, without mention in the release notes.

---

## V1: Pre-auth SysAdmin authentication bypass

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8), scored for
installations with an active SysAdmin account.
CWE-288, also CWE-602 (client-side enforcement of server-side security).

### Background

The vendor documents an emergency password reset for the SysAdmin account
([doku.asv.bayern.de](https://doku.asv.bayern.de/alle/benutzer_rollen/passwort_vergessen),
[archived 2026-03-09](https://web.archive.org/web/20260309052709/https://doku.asv.bayern.de/alle/benutzer_rollen/passwort_vergessen),
[PDF](assets/asv-doku-passwort-vergessen-wayback.pdf)): the principal enters the
school number, presses Shift+Strg+F7, and the login dialog shows a random
number. The principal reads it to a ministry administrator over the phone,
who derives an ad-hoc password from it. Logging in with that password
grants SysAdmin access.

The phone call is the only safeguard. The server does not enforce it.

### Findings

1. The server methods behind this flow (`checkClientKey`, `generateNumber`
   on `/svp/authpwdrequest`) can be called without authentication. The
   server returns the random number to the caller.
2. The ad-hoc password is derived deterministically from that number. The
   algorithm ships with the client and could be reproduced. (Not published
   here.)
3. On login (`/svp/auth`), a password matching the ad-hoc password returns
   the SysAdmin identity. The supplied login name is ignored.
4. The SysAdmin lookup does not filter by school number.

### Evidence

Test instance, 2026-04-24, no session, no credentials:

```
[1] checkClientKey("0199")   -> HTTP 200, Boolean true
[2] generateNumber("0199")   -> HTTP 200, String "52132223"
[3] ad-hoc password derived locally from "52132223"
[4] initialize(["0199", <derived password>, "127.0.0.1"])
                             -> StateException "Anmeldefehler: Alle Module werden ignoriert"
```

Steps 1 to 3 were demonstrated against the test instance. Step 4 did not
yield a SysAdmin login there: the response was byte-identical to a login
with a wrong password. The test instance is regionally hosted, and the
vendor documentation states that such schools have no sys account (inactive
`type=1` record). The SysAdmin login (findings 3 and 4) is therefore based
on static analysis of the shipped classes, not on a live login. The vendor
removed the code path in 26.2.

### Impact

On installations with an active SysAdmin account (per vendor documentation:
decentrally hosted schools), an unauthenticated attacker with network access
gains the highest application role: creating and deleting schools, managing
administrators, and thereby access to personal data of pupils, parents and
teachers.

### Fix

Server-side override path removed in 26.2. SysAdmin reset is now done by the
hosting operator, as already the case for regionally hosted schools.

---

## V2: Pre-auth Java deserialization without class allowlist

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` (8.1). AC:H because no
gadget chain leading to code execution was demonstrated.
CWE-502.

### Description

`/svp/authpwdrequest` deserialized Hessian objects of arbitrary classes from
the server classpath, without authentication and without a class allowlist.

### Evidence

Request body (zlib-compressed on the wire, 171 bytes), decoded and
annotated:

```
POST /svp/authpwdrequest
Content-Type: application/octet-stream

c 00 01                                  Hessian call
m 00 10 "generatePassword"               method
M                                        argument: map
  M t 00 13 "groovy.util.Expando"          key: Expando object
    S 00 11 "expandoProperties"
    M t 00 11 "java.util.HashMap"
      S 00 08 "hashCode"
      M t 00 4c "org.codehaus.groovy.runtime.ProxyGeneratorAdapter$ReturnValueWrappingClosure"
        S 00 05 "value"  S 00 0c "notAnInteger"
      z
    z
  z
  S 00 01 "v"                              value
z
z
```

(Length prefixes in hex. Decompressed body: 210 bytes.)

Response:

```
HTTP/1.1 500 Server Error
Date: Fri, 24 Apr 2026 08:19:39 GMT

java.lang.ClassCastException: class java.lang.String cannot be cast to
class java.lang.Integer
```

[Burp screenshot](assets/burp-classcast-asv-adv.jpg)

While building the argument map, the deserializer calls
`HashMap.put(expando, "v")`, which calls `Expando.hashCode()`. Expando looks
up the closure stored under `hashCode`, calls it and casts the result to
`Integer`. The closure returns the string `"notAnInteger"`, hence the
exception.

This happens during deserialization, before `generatePassword` or any
authentication runs. It shows that an unauthenticated caller can instantiate
classes from the server classpath (here: Groovy) and trigger method calls on
them. With a suitable gadget chain this can lead to code execution; I did
not attempt or demonstrate that.

### Fix

Class allowlist in the Hessian deserializer, 26.2 (vendor confirmation).
Recommended in addition: authentication before deserialization for
non-public endpoints, removal of unneeded libraries (e.g. Groovy) from the
server classpath, no stack traces in error responses.

---

## Timeline

| Date | Event |
|---|---|
| 2026-04-24 | Testing against authorized test instance |
| 2026-04-30 | Report to BSI / CERT-Bund; declined on 2026-05-05 (not federal scope) |
| 2026-05-08 | Report to LSI Bayern (Bayern-CERT) |
| 2026-05-22 | LSI confirms vendor contact, informs other federal states |
| 2026-06-30 | ASV Bayern 26.2 released (fixes not mentioned in release notes) |
| 2026-07-21 | Fixed releases for ASV-BW and edoosys.RLP |
| 2026-10-14 | Coordinating CERTs grant disclosure permission |
| 2026-11-11 | Advisory published |

## Note

This advisory was written with the help of Claude (Anthropic).

## References

- CWE-288: https://cwe.mitre.org/data/definitions/288.html
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- Vendor documentation (archived): https://web.archive.org/web/20260309052709/https://doku.asv.bayern.de/alle/benutzer_rollen/passwort_vergessen
- Frohoff / Lawrence, Marshalling Pickles (2015): https://frohoff.github.io/appseccali-marshalling-pickles/

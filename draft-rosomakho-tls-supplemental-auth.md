---
title: "Supplemental Authentication in TLS 1.3"
abbrev: "Supplemental Authentication in TLS 1.3"
category: std

docname: draft-rosomakho-tls-supplemental-auth-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Transport Layer Security"
keyword:
 - tls
 - supplemental authentication
 - secondary certificates
venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "yaroslavros/tls-supplemental-auth"
  latest: "https://yaroslavros.github.io/tls-supplemental-auth/draft-rosomakho-tls-supplemental-auth.html"

author:
 -
    fullname: Yaroslav Rosomakho
    organization: Zscaler
    email: yrosomakho@zscaler.com
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "k.tirumaleswar_reddy@nokia.com"
 -
    fullname: Rifaat Shekh-Yusef
    organization: Ciena
    country: Canada
    email: rifaat.s.ietf@gmail.com
 -
    fullname: Hannes Tschofenig
    organization: University of the Bundeswehr Munich
    abbrev: UniBw M.
    country: Germany
    email: hannes.tschofenig@gmx.net

normative:

informative:
  TLS-Ext-Registry:
     author:
        org: IANA
     title: Transport Layer Security (TLS) Extensions
     target: https://www.iana.org/assignments/tls-extensiontype-values
     date: March 2026

--- abstract

TLS 1.3 allows endpoints to authenticate using certificates during the handshake and supports optional post-handshake client authentication. However, some deployments require presenting additional certificate-based authentication statements bound to the same TLS connection, such as separate device and user identities, attestation evidence, or multiple certificate chains during cryptographic transitions.

This document defines Supplemental Authentication for TLS 1.3, a mechanism that allows endpoints to present additional certificate authentication messages after the handshake while preserving the authentication semantics of TLS 1.3. Supplemental authentication reuses the existing Certificate, CertificateVerify, and Finished message structure and allows endpoints to exchange one or more additional certificate-based authentication statements before sending application data or other post-handshake TLS messages.

--- middle

# Introduction

TLS 1.3 {{!TLS=I-D.ietf-tls-rfc8446bis}} allows endpoints to authenticate using certificates during the handshake. A server presents its certificate chain in the handshake `Certificate` message, and the server may request a client certificate using the `CertificateRequest` message. TLS 1.3 also defines post-handshake client authentication, which allows a server to request a client certificate after the handshake has completed.

Some deployments require presenting multiple certificate-based authentication statements bound to the same TLS connection. Examples include separating device and user authentication, presenting attestation evidence in addition to a device identity, or providing multiple certificate chains during cryptographic transitions such as migration to post-quantum algorithms. In these scenarios, multiple authentication statements may need to be associated with a single secure connection.

While TLS 1.3 post-handshake authentication can be used to request additional client certificates, it is rarely deployed in practice. Post-handshake authentication is explicitly prohibited in HTTP/2 ({{Section 9.2.3 of ?H2=RFC9113}}) and QUIC ({{Section 4.4 of ?QUIC-TLS=RFC9001}}).

This document defines Supplemental Authentication for TLS 1.3. Supplemental authentication allows endpoints to present additional certificate-based authentication messages after the sender's `Finished` message and before that sender transmits application data or any other post-handshake TLS message. These additional authentication statements are cryptographically bound to the TLS connection and reuse the existing `Certificate`, `CertificateVerify`, and `Finished` message structure defined by TLS 1.3.

Endpoints signal support for supplemental authentication and optionally request additional authentication statements using a new `supplemental_certificate_requests` extension. A peer that is willing to provide supplemental authentication in response to this extension indicates this by setting the `supplemental_certificate` flag in its main handshake `Certificate` message, and then sends any supplemental authentication flights after its own `Finished` message and before it transmits application data. When both endpoints use supplemental authentication, each endpoint follows this rule independently.

Supplemental authentication extends the existing TLS certificate authentication mechanism. It does not replace primary certificate authentication performed during the handshake and does not change the semantics of TLS authentication or authorization decisions, which remain application-specific.

Supplemental authentication requires certificate-based authentication in the main handshake. An endpoint MUST NOT send supplemental authentication sequences unless that endpoint presented a non-empty certificate chain in the main handshake `Certificate` message. Consequently, this mechanism cannot be used by an endpoint authenticated only with a PSK.

The mechanism defined in this document can also be used with DTLS 1.3 {{?DTLS=I-D.ietf-tls-rfc9147bis}} and protocols that use the TLS 1.3 handshake such as QUIC {{QUIC-TLS}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Overview of Supplemental Authentication

Supplemental authentication allows endpoints to present additional certificate-based authentication statements associated with an established TLS connection.

A fundamental concept of this specification is the clear separation between the "Main Handshake" and the "Supplemental Authentication phase". The Main Handshake is considered complete upon the successful processing of the initial Finished messages by both endpoints, at which point a secure connection is established and application traffic keys are available.

These additional authentication statements are exchanged during the Supplemental Authentication phase, after the sender's `Finished` message and before that sender transmits application data or any other post-handshake TLS message, and are cryptographically bound to the connection using the same authentication mechanisms defined in TLS 1.3.

Endpoints signal support for supplemental authentication and optionally request additional authentication statements using the `supplemental_certificate_requests` extension. This extension can appear in the `ClientHello` or `CertificateRequest` messages and contains `SupplementalCertificateRequest` structures that describe the requested authentication contexts and associated parameters.

A peer that is willing to provide supplemental authentication indicates acceptance by including the `supplemental_certificate` flag in its main handshake `Certificate` message. The presence of this flag indicates that the sender will transmit at least one additional authentication flight after the handshake completes.

Each supplemental authentication flight consists of the TLS 1.3 authentication message sequence:

~~~
Certificate
CertificateVerify
Finished
~~~
{: #fig-tls-auth-messages title="TLS 1.3 authentication message sequence"}

These messages are processed using the same cryptographic mechanisms defined for certificate authentication in TLS 1.3. Supplemental authentication flights are sent after the handshake `Finished` message and are protected using the established connection keys.

Multiple supplemental authentication flights may be sent by a single endpoint. If the `supplemental_certificate` flag is present in a supplemental `Certificate` message, it indicates that another supplemental authentication flight will follow. If the flag is absent, the `Certificate` message is the final supplemental authentication flight sent by that endpoint.

Supplemental authentication flights from a given sender MUST form a contiguous sequence of handshake messages from that sender. An endpoint MUST NOT interleave application data or other TLS messages from that endpoint with its supplemental authentication flights.

Each supplemental authentication flight satisfies at most one `SupplementalCertificateRequest`. A sender MAY transmit multiple supplemental authentication flights that satisfy the same request, provided that the number of flights does not exceed the `max_certificates` value specified in the corresponding request.

Supplemental authentication flights for different request contexts MAY appear in any order. The receiver determines which `SupplementalCertificateRequest` a supplemental authentication flight satisfies based on the `certificate_request_context` value.

The following sections illustrate typical message flows.

## Server Supplemental Authentication Example

In this example, the client requests additional authentication statements from the server using the `supplemental_certificate_requests` extension in the `ClientHello`. The server indicates acceptance in its handshake `Certificate` message and sends two supplemental authentication flights after the handshake.

~~~aasvg
Client                                           Server
------                                           ------

ClientHello
  + supplemental_certificate_requests
                       -------->
                                             ServerHello
                                             EncryptedExtensions
                                             Certificate
                                               + supplemental_certificate
                                             CertificateVerify
                                             Finished
                                             Certificate
                                               + supplemental_certificate
                                             CertificateVerify
                                             Finished
                                             Certificate
                                             CertificateVerify
                                             Finished
                       <--------

~~~
{: #fig-tls-server-supplemental-auth-example title="Server Supplemental Authentication example"}

## Client Supplemental Authentication Example

In this example, the server requests client authentication in the main handshake and additionally requests supplemental authentication statements from the client using the `supplemental_certificate_requests` extension in the `CertificateRequest` message. After the client completes the handshake, it sends two supplemental authentication flights.

~~~aasvg

Client                                           Server
------                                           ------

ClientHello
                       -------->
                                             ServerHello
                                             EncryptedExtensions
                                             CertificateRequest
                                               + supplemental_certificate_requests
                                             Certificate
                                             CertificateVerify
                                             Finished
                       <--------
Certificate
 + supplemental_certificate
CertificateVerify
Finished
Certificate
 + supplemental_certificate
CertificateVerify
Finished
Certificate
CertificateVerify
Finished
                       -------->

~~~
{: #fig-tls-client-supplemental-auth-example title="Client Supplemental Authentication example"}

# The supplemental_certificate_requests Extension

The `supplemental_certificate_requests` TLS extension is used to signal support for supplemental authentication and to optionally request additional certificate-based authentication statements from the peer.

This extension MAY appear in the `ClientHello` or `CertificateRequest` messages:

* When included in a `ClientHello`, the extension indicates that the client supports supplemental authentication and optionally requests supplemental authentication statements from the server.
* When included in a `CertificateRequest`, the extension indicates that the server supports supplemental authentication and optionally requests supplemental authentication statements from the client.

When included in a `CertificateRequest`, this extension augments rather than replaces the semantics of the enclosing `CertificateRequest`. In particular, a `CertificateRequest` sent during the main handshake still requests client authentication for the main handshake.

The extension contains a list of `SupplementalCertificateRequest` structures describing requested supplemental authentication contexts.

The extension structure is defined as follows:

~~~
struct {
  uint8 max_certificates;
  opaque certificate_request_context<0..255>;
  Extension extensions<0..2^16-1>;
} SupplementalCertificateRequest;

struct {
  SupplementalCertificateRequest requests<0..2^16-1>;
} SupplementalCertificateRequests;
~~~
{: #fig-supplemental-certificate-requests title="supplemental_certificate_requests Extension Structure"}

The requests field contains zero or more `SupplementalCertificateRequest` structures.

If the list is empty, the sender indicates willingness to receive supplemental authentication statements without specifying any particular request contexts.

Each `SupplementalCertificateRequest` describes a requested supplemental authentication context and the parameters associated with that request.

The fields of `SupplementalCertificateRequest` are defined as follows:

**max_certificates**:

: A limit on the number of supplemental authentication flights that the peer may send in response to this request. The value specifies the maximum number of Certificate authentication flights that may satisfy this request. The value MUST be greater than zero.

**certificate_request_context**:

: An opaque value used to identify this supplemental authentication request. This value is carried in the `certificate_request_context` field of the `Certificate` message sent in response to this request.

Within a single `supplemental_certificate_requests` extension, each `certificate_request_context` value MUST be unique. If more than one `SupplementalCertificateRequest` structure is present, at most one of them MAY use an empty `certificate_request_context`.

**extensions**:

: A list of extensions that describe parameters associated with this request. Except as described below for `server_name`, these extensions follow the same syntax and semantics as extensions carried in the TLS 1.3 `CertificateRequest` message. Only extensions that are valid in a `CertificateRequest` message MAY appear in this list. The `supplemental_certificate_requests` extension MUST NOT appear in the `extensions` list of a `SupplementalCertificateRequest`.

The `server_name` extension MAY appear in the `extensions` list of a `SupplementalCertificateRequest` when the containing `supplemental_certificate_requests` extension appears in the `ClientHello`. The `server_name` extension MUST NOT appear in the `extensions` list of a `SupplementalCertificateRequest` when the containing `supplemental_certificate_requests` extension appears in a `CertificateRequest`.

If an extension is not present in the `extensions` list of a `SupplementalCertificateRequest`, the parameters for that extension are inherited from the corresponding values negotiated in the main handshake. Unlike the TLS 1.3 `ClientHello` and `CertificateRequest` messages, the `signature_algorithms` extension is OPTIONAL in a `SupplementalCertificateRequest`.

When the `supplemental_certificate_requests` extension appears in the `ClientHello`, the inherited values are taken from the client's
`ClientHello`. When the extension appears in a `CertificateRequest`, the inherited values are taken from the parameters of the enclosing `CertificateRequest` message.

A peer receiving the `supplemental_certificate_requests` extension MAY respond to zero or more of the contained `SupplementalCertificateRequest` structures. For a given request, the peer MAY send between zero and `max_certificates` supplemental authentication flights.

If a peer sends a supplemental authentication flight in response to a request, the `certificate_request_context` field of the `Certificate` message MUST be equal to the `certificate_request_context` value of the corresponding `SupplementalCertificateRequest`.

The following is an example of SupplementalCertificateRequests:

~~~
SupplementalCertificateRequests {
  requests = [
    // Request for the Device Certificate
    SupplementalCertificateRequest {
      max_certificates = 1,
      certificate_request_context = "device-identity",
      extensions = { device cert specific extensions ... }
    },

    // Request for the User Certificate
    SupplementalCertificateRequest {
      max_certificates = 1,
      certificate_request_context = "user-identity",
      extensions = { user cert specific extensions ... }
    }
  ]
}
~~~


# The supplemental_certificate TLS flag

The `supplemental_certificate` TLS flag signals the use of supplemental authentication.

This flag is defined as a TLS flag as specified in {{!TLS-FLAGS=I-D.ietf-tls-tlsflags}} and may appear in a `Certificate` message.

The semantics of this flag depend on the context in which it appears.

## Use in the Main Handshake

When the `supplemental_certificate` flag appears in the main handshake `Certificate` message, it indicates that the sender will transmit at least one additional certificate authentication sequence after the TLS handshake has completed.

An endpoint MUST NOT set the `supplemental_certificate` flag in its main handshake `Certificate` message unless the peer indicated willingness to receive supplemental authentication by including the `supplemental_certificate_requests` extension.

## Use in Supplemental Authentication Certificates

When the `supplemental_certificate` flag appears in a `Certificate` message sent after the handshake, it indicates that another supplemental authentication sequence will follow.

If the flag is absent from a supplemental `Certificate` message, that `Certificate` message is the final supplemental authentication sequence sent by that endpoint.

# Supplemental Authentication Flights {#supplemental-authentication-flights}

Supplemental authentication is performed using one or more additional certificate authentication sequences exchanged after the TLS handshake has completed.

Each supplemental authentication sequence consists of the following TLS 1.3 authentication messages:

~~~
Certificate
CertificateVerify
Finished
~~~

These messages use the same structure and processing rules as the corresponding TLS 1.3 handshake messages defined in {{TLS}}.

## Record Protection

Supplemental authentication messages are sent after the TLS handshake has completed and are protected using the established application traffic secrets. In TLS and DTLS, these messages are carried as protected handshake messages and are encrypted under the sender's current application traffic keys.

## Transcript Construction

Supplemental authentication does not extend the TLS 1.3 handshake transcript used for the key schedule, exporters, or session resumption. For the purpose of constructing supplemental authentication messages, each endpoint maintains a sender-local supplemental transcript.

For a server sending supplemental authentication sequences, the sender-local supplemental transcript begins with the handshake transcript that includes all handshake messages up to and including the server's main-handshake `Finished` message.

For a client sending supplemental authentication sequences, the sender-local supplemental transcript begins with the handshake transcript that includes all handshake messages up to and including the client's main-handshake `Finished` message.

The sender-local supplemental transcript does not include post-handshake messages from the peer, including supplemental authentication sequences sent by the peer. Each endpoint therefore signs only its own supplemental authentication sequences together with the relevant TLS handshake transcript prefix.

For each supplemental authentication sequence, the sender-local supplemental transcript additionally includes:

* all messages from any preceding supplemental authentication sequences sent by this endpoint, and
* the `Certificate`, `CertificateVerify` and `Finished` message of the current supplemental authentication sequence.

The `CertificateVerify` message is constructed using the same procedure and context string defined for certificate authentication in TLS 1.3 {{TLS}}. A server uses the server `CertificateVerify` context string, and a client uses the client `CertificateVerify` context string.

~~~
CertificateVerify: A signature over the value
   Transcript-Hash(Handshake Context, Certificate).
~~~

The `Finished` message is constructed using the same procedure as `Finished` in TLS 1.3, except that the transcript hash is taken over the sender-local supplemental transcript defined above. The Base Key is the sender's current application traffic secret, namely `server_application_traffic_secret_0` for a server and `client_application_traffic_secret_0` for a client.

~~~
Finished: A MAC over the value Transcript-Hash(Handshake Context,
   Certificate, CertificateVerify) using a MAC key derived from the
   Base Key.
~~~

Handshake Context and Base Key are specified in the following table:

~~~
+--------------+-----------------------------+--------------------------------+
| Mode         | Handshake Context           | Base Key                       |
+--------------+-----------------------------+--------------------------------+
| Server       | ClientHello ... server      | server_application_traffic_    |
| Supplemental | Finished +                  | secret_N                       |
|              | all messages from           |                                |
|              | previously sent server      |                                |
|              | supplemental authentication |                                |
|              | sequences                   |                                |
|              |                             |                                |
| Client       | ClientHello ... client      | client_application_traffic_    |
| Supplemental | Finished +                  | secret_N                       |
|              | all messages from           |                                |
|              | previously sent client      |                                |
|              | supplemental authentication |                                |
|              | sequences                   |                                |
+--------------+-----------------------------+--------------------------------+
~~~

After a supplemental authentication sequence is sent, its `Certificate`, `CertificateVerify`, and `Finished` messages are appended to the sender's Handshake Context, so that each subsequent sequence is bound to all previously transmitted sequences from that sender. Endpoints performing supplemental authentication MUST retain the transcript hash state at the end of the handshake and update it with each supplemental authentication message sent, until all supplemental authentication sequences have been transmitted.

An endpoint MUST NOT change its sending application traffic keys in the middle of a supplemental authentication sequence. If an endpoint sends more than one supplemental authentication sequence, it MAY update its sending application traffic keys between sequences.

Endpoints performing supplemental authentication MUST retain the necessary handshake authentication state required to compute additional `CertificateVerify` and `Finished` messages until supplemental authentication has completed.

## Request Matching

If the peer previously sent a `supplemental_certificate_requests` extension, a supplemental authentication sequence MAY satisfy one of the contained `SupplementalCertificateRequest` structures.

If a supplemental authentication sequence is sent in response to a request, the `certificate_request_context` field of the `Certificate` message MUST be equal to the `certificate_request_context` value of the corresponding SupplementalCertificateRequest.

A sender MAY transmit multiple supplemental authentication sequences that satisfy the same request, provided that the number of sequences does not exceed the `max_certificates` value specified in the request.

A sender MAY also transmit supplemental authentication sequences that are not associated with any specific request context, in which case the `certificate_request_context` field of the `Certificate` message is empty.

## Message Ordering

Supplemental authentication sequences sent by an endpoint MUST form a contiguous sequence of TLS handshake messages from that endpoint.

An endpoint MUST NOT interleave application data or other TLS messages from that endpoint with its supplemental authentication sequences.

If the `supplemental_certificate` TLS flag in a `Certificate` message indicates that another supplemental authentication sequence will follow, the `Finished` message completing that sequence MUST be followed by a `Certificate` message starting the next supplemental authentication sequence.

Messages from the peer MAY appear between supplemental authentication sequences and are processed according to TLS 1.3. Such peer messages are not included in the sender-local supplemental transcript defined in {{supplemental-authentication-flights}}.

If any other TLS message is received from that endpoint before the next `Certificate` message, the receiver MUST abort the connection with an `unexpected_message` alert.

# Security Considerations

## Authentication Binding

Each supplemental authentication sequence includes a `CertificateVerify` and `Finished` message constructed using the sender-local supplemental transcript and the sender's application traffic secrets as described in {{supplemental-authentication-flights}}. This ensures that each supplemental certificate authentication statement is cryptographically bound to the TLS connection and cannot be replayed across connections.

Supplemental authentication sequences sent by one endpoint are not included in the transcript used by the peer when constructing its own supplemental authentication messages. As a result, supplemental authentication statements produced by each endpoint are independently bound to the TLS handshake transcript rather than to the peer's supplemental authentication statements.

This design allows both endpoints to transmit supplemental authentication sequences without introducing additional round-trip latency. Applications that rely on relationships between multiple authentication statements from different endpoints MUST verify those relationships explicitly at the application layer.

## Message Ordering and Integrity

The `supplemental_certificate` TLS flag ensures that supplemental authentication sequences cannot be truncated or reordered without detection. If a `Certificate` message indicates that another supplemental authentication sequence will follow, the receiver expects the next message from that endpoint to begin the next sequence. Any deviation from this ordering results in a TLS protocol error.

Because each supplemental authentication sequence includes a `Finished` message that covers the transcript defined in {{supplemental-authentication-flights}}, modification, removal, or reordering of messages within a sequence is detected by the TLS authentication mechanisms.

## Authorization Semantics

TLS authentication establishes the identity of the peer but does not define how that identity is used for authorization. Supplemental authentication introduces additional authentication statements that may represent different identities or attributes (for example, device identity, user identity, or attestation evidence).

Applications using supplemental authentication MUST define how these authentication statements are interpreted and how multiple statements are combined when making authorization decisions. Incorrect or ambiguous interpretation of multiple authentication statements could lead to unintended authorization outcomes.

## Resource Consumption

A peer can request supplemental authentication using the `supplemental_certificate_requests` extension. Responding to such requests may require the peer to construct certificate chains and produce signatures. Implementations SHOULD ensure that the processing of supplemental authentication requests is subject to appropriate resource limits and policy checks to prevent denial-of-service conditions.

The `max_certificates` field in `SupplementalCertificateRequest` limits the number of supplemental authentication sequences that may satisfy a given request. Implementations MUST enforce this limit.

## Confidentiality of Authentication Requests

The `supplemental_certificate_requests` extension may reveal information about the types of authentication statements requested by an endpoint. When this extension appears in the `ClientHello`, its contents are visible to on-path observers unless the connection uses Encrypted ClientHello {{?ECH=RFC9849}}.

Clients that wish to avoid revealing requested supplemental authentication contexts SHOULD use ECH so that the contents of the inner ClientHello are encrypted.

A client MAY include an empty `supplemental_certificate_requests` extension in the outer ClientHello to indicate support for supplemental authentication while withholding the specific request parameters until the encrypted inner ClientHello is processed.

## Session Resumption

The `resumption_master_secret` is derived from `ClientHello...client Finished` per Section 7.1 of {{TLS}} and does not include supplemental authentication messages. A server MUST NOT send a `NewSessionTicket` message until all supplemental authentication sequences from both endpoints have been completed. This ensures that a resumed session is not established before the supplemental authentication guarantees of the original session have been fully established.

# IANA Considerations

## TLS Extension

IANA is requested to add the following entry to the "TLS ExtensionType Values" extension registry {{TLS-Ext-Registry}}:

- Value: TBD1
- Extension Name: supplemental_certificate_requests
- TLS 1.3: CH, CR
- DTLS-Only: N
- Recommended: Y
- Reference: \[This document\]

## TLS Flag

IANA is requested to add the following entry to the "TLS Flags" registry created by {{TLS-FLAGS}}:

- Value: TBD2
- Flag Name: supplemental_certificate
- Messages: CT
- Recommended: Y
- Reference: \[This document\]

--- back

# Acknowledgments

# Appendix

## Application Policy Enforcement

Applications making use of supplemental authentication must define a clear and unambiguous policy for interpreting the set of authentication statements presented in the TLS handshake and subsequent supplemental authentication flights. This policy dictates the requirements for establishing a connection and for granting access to specific resources.
When evaluating a connection, the application's policy engine must consider all received authentication statements, as well as the absence of expected statements, as inputs to its authorization decision. Incorrect or incomplete policy evaluation can lead to severe security vulnerabilities.

Endpoints should perform their complete policy evaluation after all supplemental authentication flights are complete and before processing any application data. If the full set of presented identities does not satisfy the application's policy, the endpoint must terminate the connection, preferably with a specific alert (e.g., bad_certificate or access_denied).

## Policy Enforcement Scenarios

The following non-normative examples illustrate how application policy interacts with the supplemental authentication mechanism.

### Hybrid Post-Quantum and Traditional Authentication

A high-security client has a local policy requiring that all connections to a specific server be mutually authenticated using both a traditional ECDSA certificate and a post-quantum ML-DSA certificate.

* Client Policy: Connection requires client authentication with both an ECDSA certificate and a ML-DSA certificate.

* Handshake: The server sends a CertificateRequest message.

* Success: The server includes the supplemental_certificate_requests extension. The main request asks for an ECDSA certificate, and a supplemental request asks for a ML-DSA certificate. The client is able to satisfy both and proceeds.

* Failure: The server's CertificateRequest only asks for an ECDSA certificate and does not include a supplemental request for ML-DSA. Upon receiving the CertificateRequest, the client's policy engine determines that its mandatory requirement for dual authentication cannot be met. The client must abort the handshake by sending a handshake_failure alert. It is a policy violation to proceed with a connection that is only partially authenticated according to its own requirements.


### Device and User Identity

A service provider uses supplemental authentication to separate device and user identity for a remote access service. The policy grants different levels of access based on the combination of identities presented.

Server Policy:

* Any connection requires a valid, corporate-managed device certificate.
* Access to the general user portal requires a valid user certificate in addition to the device certificate.
* Access to the admin portal requires a valid user certificate with the "admin" role, in addition to the device certificate.


Handshake:

The server sends a CertificateRequest asking for the device certificate in the main handshake and includes a supplemental_certificate_requests extension asking for a user certificate.


Server Action:

* If a client provides only a valid device certificate, the connection is established, but the application will deny access to any resource pending the user authentication.
* If a client provides a valid device certificate and a valid standard user certificate, the application grants access to the general user portal but denies access to the admin portal.
* If a client provides a valid device certificate and a valid admin user certificate, the application grants access to both portals.
* If a client provides an invalid device certificate, the server must abort the handshake, regardless of what user certificate is offered. The primary authentication failed to meet the baseline policy.



{:numbered="false"}

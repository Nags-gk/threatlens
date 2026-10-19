# Threat catalog

35 rules, generated from `threatlens/kb.yml`.

| ID | Threat | STRIDE | Lens | Applies to | References |
|---|---|---|---|---|---|
| TL-S01 | Unauthenticated flow crosses a trust boundary | Spoofing | access | flow | CWE-306 Missing Authentication for Critical Function · CAPEC-115 Authentication Bypass |
| TL-S02 | Internet-facing login without multi-factor authentication | Spoofing | access | component | CWE-308 Use of Single-factor Authentication · T1078 Valid Accounts |
| TL-S03 | Devices share one fleet-wide credential | Spoofing | access | component | CWE-798 Use of Hard-coded Credentials · CAPEC-191 Read Sensitive Constants Within an Executable |
| TL-S04 | Device credential is not bound to hardware | Spoofing | access | component | CWE-522 Insufficiently Protected Credentials · T1036 Masquerading |
| TL-S05 | Service-to-service call uses a static API key | Spoofing | access | flow | CWE-798 Use of Hard-coded Credentials |
| TL-T01 | Flow crosses a trust boundary in plaintext | Tampering | data | flow | CWE-319 Cleartext Transmission of Sensitive Information · CAPEC-94 Adversary in the Middle |
| TL-T02 | Firmware updates are not signature-verified | Tampering | access | component | CWE-494 Download of Code Without Integrity Check · CAPEC-186 Malicious Software Update |
| TL-T03 | Firmware rollback is not prevented | Tampering | abuse | component | CWE-1328 Security Version Number Mutable to Older Versions |
| TL-T04 | Internet-facing service writes to a datastore without input validation | Tampering | data | component | CWE-20 Improper Input Validation |
| TL-R01 | Sensitive actions are not audit-logged | Repudiation | logging | component | CWE-778 Insufficient Logging |
| TL-L01 | Authentication events lack security logging fields | Repudiation | logging | component | CWE-223 Omission of Security-relevant Information |
| TL-L02 | No detection consumes the security logs | Repudiation | logging | system | CWE-778 Insufficient Logging |
| TL-L03 | Log retention too short for investigations | Repudiation | logging | component | CWE-779 Logging of Excessive Data |
| TL-L04 | Logs are not tamper-evident | Repudiation | logging | component | CWE-117 Improper Output Neutralization for Logs |
| TL-I01 | Sensitive data stored without encryption at rest | Information disclosure | data | component | CWE-311 Missing Encryption of Sensitive Data |
| TL-I02 | Object API uses guessable identifiers | Information disclosure | abuse | component | CWE-639 Authorization Bypass Through User-Controlled Key · T1087 Account Discovery |
| TL-E04 | Missing object-level authorization | Elevation of privilege | access | component | CWE-862 Missing Authorization · CAPEC-122 Privilege Abuse |
| TL-I04 | Secrets stored outside a secret manager | Information disclosure | data | component | CWE-312 Cleartext Storage of Sensitive Information |
| TL-I05 | Internet-facing component may leak internals in errors | Information disclosure | data | component | CWE-209 Generation of Error Message Containing Sensitive Information |
| TL-I06 | Sensitive data sent to a third party without minimization | Information disclosure | data | flow | CWE-359 Exposure of Private Personal Information |
| TL-D01 | Internet-facing component without rate limiting | Denial of service | abuse | component | CWE-770 Allocation of Resources Without Limits or Throttling |
| TL-D02 | Device check-in without per-device rate limits | Denial of service | abuse | component | CWE-770 Allocation of Resources Without Limits or Throttling |
| TL-E01 | Admin console reachable from the internet without context-aware access | Elevation of privilege | access | component | CWE-284 Improper Access Control · T1133 External Remote Services |
| TL-E02 | Over-broad IAM permissions | Elevation of privilege | access | component | CWE-250 Execution with Unnecessary Privileges · T1098 Account Manipulation |
| TL-E03 | Workload runs as root | Elevation of privilege | access | component | CWE-250 Execution with Unnecessary Privileges |
| TL-A01 | Signup and promo flows lack anti-automation | Spoofing | abuse | component | CWE-799 Improper Control of Interaction Frequency · T1585 Establish Accounts |
| TL-A02 | Login lacks credential-stuffing defenses | Spoofing | abuse | component | CWE-307 Improper Restriction of Excessive Authentication Attempts · T1110.004 Credential Stuffing |
| TL-A03 | Account recovery or MFA change without re-authentication | Spoofing | abuse | component | CWE-620 Unverified Password Change · T1098 Account Manipulation |
| TL-A04 | Device pairing without proof of physical possession | Spoofing | abuse | component | CWE-287 Improper Authentication |
| TL-A05 | SMS OTP endpoint can be pumped | Denial of service | abuse | component | CWE-799 Improper Control of Interaction Frequency |
| TL-A06 | Number port or eSIM transfer without step-up | Spoofing | abuse | component | CWE-287 Improper Authentication · T1111 Multi-Factor Authentication Interception |
| TL-A07 | High-risk changes without user notification | Repudiation | abuse | component | CWE-778 Insufficient Logging |
| TL-A08 | Enrollment accepts unattested devices | Spoofing | access | component | CWE-290 Authentication Bypass by Spoofing |
| TL-A09 | Bulk data export without anomaly detection | Information disclosure | abuse | component | CWE-799 Improper Control of Interaction Frequency · T1530 Data from Cloud Storage |
| TL-A10 | Long-lived device or API keys are never rotated | Spoofing | access | component | CWE-324 Use of a Key Past its Expiration Date |

## TL-S01: Unauthenticated flow crosses a trust boundary

**When:** `{'crosses_boundary': True, 'auth_in': ['none']}`

**Threat:** Anything that can reach the receiving side can send requests as any caller, because nothing proves who the sender is.

**Recommendation:** Authenticate the flow (OAuth 2.0 for users, mTLS or workload identity for services, per-device certificates for devices) and reject unauthenticated requests at the boundary.

## TL-S02: Internet-facing login without multi-factor authentication

**When:** `{'handles_any': ['login'], 'internet_facing': True, 'lacks': ['mfa']}`

**Threat:** A leaked or phished password is enough to take over an account.

**Recommendation:** Offer and default to a second factor (passkeys or TOTP); require it on new devices and for sensitive changes.

## TL-S03: Devices share one fleet-wide credential

**When:** `{'type_in': ['device'], 'device_auth_in': ['shared_secret']}`

**Threat:** Extracting the secret from one device lets an attacker impersonate every device in the fleet.

**Recommendation:** Provision a unique per-device credential at manufacture and support revoking a single device.

## TL-S04: Device credential is not bound to hardware

**When:** `{'type_in': ['device'], 'lacks': ['hardware_keys', 'attestation']}`

**Threat:** A credential copied off the device can be replayed from a server, cloning the device identity.

**Recommendation:** Keep device keys in a secure element and verify key attestation at check-in; alert on one identity seen from two networks.

## TL-S05: Service-to-service call uses a static API key

**When:** `{'auth_in': ['api_key', 'shared_key'], 'from_internet': False, 'source_type_in': ['service', 'gateway', 'detection']}`

**Threat:** Long-lived shared keys leak through logs, configs and laptops and rarely get rotated.

**Recommendation:** Use workload identity or mTLS with short-lived certificates between services.

## TL-T01: Flow crosses a trust boundary in plaintext

**When:** `{'crosses_boundary': True, 'protocol_in': ['http', 'mqtt', 'grpc', 'ble', 'tcp', 'sql', 'smtp']}`

**Threat:** An attacker on the path can read and modify traffic, including tokens and commands.

**Recommendation:** Use TLS 1.2+ (HTTPS, MQTTS, gRPC over TLS) or BLE Secure Connections, and pin certificates on devices.

## TL-T02: Firmware updates are not signature-verified

**When:** `{'handles_any': ['firmware_update'], 'lacks': ['code_signing']}`

**Threat:** Whoever can serve an update image controls every device that installs it.

**Recommendation:** Sign images offline and verify the signature on device before install; keep the signing key in an HSM.

## TL-T03: Firmware rollback is not prevented

**When:** `{'handles_any': ['firmware_update'], 'lacks': ['rollback_protection']}`

**Threat:** An attacker installs an older, validly signed image that still has a patched vulnerability.

**Recommendation:** Store a monotonic security version on device and refuse images below it.

## TL-T04: Internet-facing service writes to a datastore without input validation

**When:** `{'type_in': ['service', 'gateway'], 'internet_facing': True, 'lacks': ['input_validation']}`

**Threat:** Unvalidated input reaches queries and parsers, enabling injection and corrupted records.

**Recommendation:** Validate every request against a strict schema at the edge and use parameterized queries.

## TL-R01: Sensitive actions are not audit-logged

**When:** `{'handles_any': ['login', 'admin', 'account_recovery', 'number_port', 'device_pairing', 'policy_push', 'data_export'], 'lacks': ['audit_logging']}`

**Threat:** After an incident nobody can say who did what, when, and from where.

**Recommendation:** Write an append-only audit record (actor, action, target, time, source IP, device) for every sensitive action.

## TL-L01: Authentication events lack security logging fields

**When:** `{'handles_any': ['login', 'signup', 'sms_otp', 'device_checkin'], 'lacks': ['security_logging']}`

**Threat:** Without source IP, ASN, device fingerprint and result on each attempt, stuffing, spraying and takeovers cannot be detected or scoped.

**Recommendation:** Log every attempt with timestamp, account, IP, ASN, device fingerprint, user agent, result, and a keyed hash of the attempted secret.

## TL-L02: No detection consumes the security logs

**When:** `{'missing_component_type': 'detection'}`

**Threat:** Logs are written but nobody is alerted; abuse is found by users or the press.

**Recommendation:** Stream security logs to a detection pipeline with rules for the abuse cases in this model and an on-call rotation.

## TL-L03: Log retention too short for investigations

**When:** `{'type_in': ['log_sink'], 'retention_below': 90}`

**Threat:** Slow campaigns and late-reported takeovers fall outside the retention window, so impact cannot be measured.

**Recommendation:** Keep security logs at least 90 days hot and 1 year cold, subject to privacy review.

## TL-L04: Logs are not tamper-evident

**When:** `{'type_in': ['log_sink'], 'lacks': ['log_integrity']}`

**Threat:** An attacker with write access can delete or edit the records of what they did.

**Recommendation:** Ship logs to a separate project with write-only access for producers and object retention locks.

## TL-I01: Sensitive data stored without encryption at rest

**When:** `{'type_in': ['datastore', 'queue', 'log_sink'], 'data_any': ['credentials', 'health', 'location', 'payment', 'secrets', 'video', 'pii', 'logs'], 'lacks': ['encryption_at_rest']}`

**Threat:** A leaked backup, snapshot or disk exposes the data directly.

**Recommendation:** Encrypt at rest with managed keys; use application-layer encryption for credentials and health data.

## TL-I02: Object API uses guessable identifiers

**When:** `{'handles_any': ['object_api'], 'lacks': ['opaque_ids']}`

**Threat:** Sequential IDs let a script walk the ID space to discover devices and accounts.

**Recommendation:** Use random 128-bit identifiers, return 404 for objects the caller does not own, and alert on high 4xx ratios.

## TL-E04: Missing object-level authorization

**When:** `{'handles_any': ['object_api', 'data_export', 'sync'], 'lacks': ['authz']}`

**Threat:** An authenticated user requests another user's objects by changing an ID (IDOR).

**Recommendation:** Check ownership of every object on every request in the service, not in the client.

## TL-I04: Secrets stored outside a secret manager

**When:** `{'type_in': ['service', 'gateway', 'detection', 'ota_server'], 'data_any': ['secrets'], 'lacks': ['secret_manager']}`

**Threat:** Keys in environment files and images leak through repositories, crash dumps and support bundles.

**Recommendation:** Load secrets at runtime from a secret manager with per-service access and rotation.

## TL-I05: Internet-facing component may leak internals in errors

**When:** `{'internet_facing': True, 'type_in': ['service', 'gateway'], 'lacks': ['generic_errors']}`

**Threat:** Stack traces and verbose errors reveal versions, paths and queries useful for further attacks.

**Recommendation:** Return generic errors with a request ID; keep detail in server logs.

## TL-I06: Sensitive data sent to a third party without minimization

**When:** `{'target_type_in': ['third_party'], 'data_any': ['health', 'location', 'contacts', 'pii', 'video']}`

**Threat:** A vendor breach or misuse exposes user data that the vendor did not need.

**Recommendation:** Send only the fields the vendor needs, pseudonymize identifiers, and record user consent.

## TL-D01: Internet-facing component without rate limiting

**When:** `{'internet_facing': True, 'type_in': ['service', 'gateway', 'identity_provider'], 'lacks': ['rate_limit']}`

**Threat:** Floods exhaust capacity, and unlimited attempts make brute force and scraping cheap.

**Recommendation:** Rate-limit per IP, per account and per ASN at the edge; return 429 with Retry-After.

## TL-D02: Device check-in without per-device rate limits

**When:** `{'handles_any': ['device_checkin'], 'lacks': ['per_device_rate_limit']}`

**Threat:** A cloned or buggy device floods check-ins and drowns the signal for the rest of the fleet.

**Recommendation:** Limit check-ins per device identity and alert when one identity exceeds its cadence.

## TL-E01: Admin console reachable from the internet without context-aware access

**When:** `{'type_in': ['admin_console'], 'internet_facing': True, 'lacks': ['context_aware_access', 'ip_allowlist']}`

**Threat:** A phished admin credential gives full control of the fleet from anywhere.

**Recommendation:** Put the console behind context-aware access (managed device + strong auth) and require hardware security keys for admins.

## TL-E02: Over-broad IAM permissions

**When:** `{'iam_in': ['broad']}`

**Threat:** Compromising this component grants access far beyond what it needs.

**Recommendation:** Grant per-resource, per-action roles and review unused permissions every quarter.

## TL-E03: Workload runs as root

**When:** `{'type_in': ['service', 'gateway', 'detection', 'ota_server'], 'lacks': ['non_root']}`

**Threat:** A code-execution bug becomes full control of the container and an easier escape path.

**Recommendation:** Run as an unprivileged user with a read-only root filesystem and no added capabilities.

## TL-A01: Signup and promo flows lack anti-automation

**When:** `{'handles_any': ['signup', 'promo'], 'lacks': ['captcha', 'phone_verification', 'bot_detection']}`

**Threat:** Scripts mass-create accounts to farm referral credit or stage later abuse.

**Recommendation:** Add bot detection, verify a phone number before payouts, and hold promo credit until accounts show organic use.

## TL-A02: Login lacks credential-stuffing defenses

**When:** `{'handles_any': ['login'], 'internet_facing': True, 'lacks': ['breached_password_check', 'bot_detection']}`

**Threat:** Leaked combo lists are replayed across the user base until reused passwords hit.

**Recommendation:** Check passwords against breach corpora, add bot detection, and step up on never-seen devices and hosting ASNs.

## TL-A03: Account recovery or MFA change without re-authentication

**When:** `{'handles_any': ['account_recovery'], 'lacks': ['reauth', 'step_up']}`

**Threat:** A hijacked session changes the recovery email or MFA and locks the real owner out permanently.

**Recommendation:** Require the current second factor for recovery and MFA changes, notify the old email, and delay the change by 24 hours on new devices.

## TL-A04: Device pairing without proof of physical possession

**When:** `{'handles_any': ['device_pairing'], 'lacks': ['physical_proof']}`

**Threat:** An attacker pairs a victim's camera or tracker to their own account remotely and watches or follows them.

**Recommendation:** Require a code shown on the device or a button press, and notify all existing household members on every new pairing.

## TL-A05: SMS OTP endpoint can be pumped

**When:** `{'handles_any': ['sms_otp'], 'lacks': ['rate_limit', 'cooldown']}`

**Threat:** Bots request OTPs to premium-rate numbers (SMS pumping toll fraud) and flood users with codes.

**Recommendation:** Rate-limit per number, per IP and per destination prefix, add cooldowns, and block high-cost destination ranges.

## TL-A06: Number port or eSIM transfer without step-up

**When:** `{'handles_any': ['number_port'], 'lacks': ['step_up']}`

**Threat:** SIM swap moves the victim's number to an attacker device and intercepts every SMS code.

**Recommendation:** Require step-up authentication, a port-out PIN, a cooling-off delay with notification, and hold transfers from risky sessions.

## TL-A07: High-risk changes without user notification

**When:** `{'handles_any': ['account_recovery', 'device_pairing', 'number_port', 'enrollment'], 'lacks': ['notify_user']}`

**Threat:** The owner does not learn their account changed until damage is done, so the attacker has time.

**Recommendation:** Notify the owner on every security-relevant change through a channel the attacker does not control.

## TL-A08: Enrollment accepts unattested devices

**When:** `{'handles_any': ['enrollment'], 'lacks': ['attestation']}`

**Threat:** An emulator or rooted device enrolls into a managed fleet and receives corporate policies, certificates and data.

**Recommendation:** Require hardware-backed key attestation and verified boot state before enrollment.

## TL-A09: Bulk data export without anomaly detection

**When:** `{'handles_any': ['data_export'], 'lacks': ['anomaly_detection']}`

**Threat:** A compromised account or insider exports everyone's data and nothing notices the volume.

**Recommendation:** Alert on export volume against the account's baseline and require step-up for large exports.

## TL-A10: Long-lived device or API keys are never rotated

**When:** `{'type_in': ['device', 'identity_provider'], 'lacks': ['key_rotation']}`

**Threat:** A key leaked years ago still works.

**Recommendation:** Rotate keys on a schedule and on every suspected compromise; keep validity short.

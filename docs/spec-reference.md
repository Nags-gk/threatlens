# Architecture spec reference

A spec answers the questions a security design review asks. Unknown values are
rejected, so a typo cannot silently disable a rule.

```yaml
name: My system
description: one paragraph
zones: {internet: 0, edge: 2, app: 3, data: 4}     # trust level 0-10; 0 = untrusted
components:
  - id: auth_service                  # unique
    type: identity_provider           # client gateway service datastore device queue admin_console
                                      # third_party log_sink ota_server identity_provider detection
    zone: app
    internet_facing: true             # reachable from the internet (directly or through a gateway)
    handles: [login, account_recovery]   # login signup account_recovery device_pairing sms_otp number_port
                                         # promo admin firmware_update device_checkin object_api data_export
                                         # enrollment policy_push sync
    data: [credentials, pii]          # pii credentials health location payment secrets telemetry video logs policy contacts
    controls: [mfa, rate_limit]       # see the list below
    device_auth: per_device           # devices only: per_device | shared_secret
    iam: least_privilege              # least_privilege | broad
    log_retention_days: 365           # log sinks only
flows:
  - id: f_login
    from: mobile_app
    to: auth_service
    protocol: https                   # https http mqtt mqtts grpc grpc_tls ble ble_secure tls tcp sms sql sql_tls internal_tls smtp smtps
    auth: oauth2                      # none oauth2 mtls api_key session password device_cert shared_key workload_identity signed_token
    data: [credentials]
accepted_risks:                       # optional risk register: still reported, not counted as open
  - {rule: TL-S01, element: f_status, reason: public status page, owner: alice}
```

Controls: `mfa rate_limit waf captcha phone_verification breached_password_check
bot_detection reauth physical_proof step_up audit_logging security_logging
encryption_at_rest access_logging hardware_keys attestation code_signing generic_errors
ip_allowlist context_aware_access authz input_validation alerting data_minimization
secret_manager non_root least_privilege_iam per_device_rate_limit opaque_ids
log_integrity anomaly_detection fraud_hold notify_user cooldown rollback_protection
consent key_rotation`

A flow **crosses a trust boundary** when its two ends sit in zones with different
trust levels. A flow is **from the internet** when it starts in a trust-0 zone.

## Scoring
Each rule has a base likelihood and impact (1-5). Likelihood rises by 1 when the
element is exposed to the internet; impact rises by 1 when it holds or carries
credentials, health, location, payment, secrets or video. Risk = likelihood x impact:
20+ critical, 12+ high, 6+ medium, otherwise low.

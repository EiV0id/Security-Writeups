# Unrestricted File Upload: Same-Origin HTML Execution via a Profile Photo Field

*Security research · Authorized testing · Reported and fixed by the owner*

> **Status:** The target no longer behaves as shown. Captures are from 2026-05. Login access was lost after the fix, so post-fix behaviour was not re-checked.
>
> **Redaction:** Domain and organisation withheld; hosts appear as `redacted.example`. Cookies, CSRF tokens and screenshots are sanitised.

## 1. Summary

A student profile photo upload on a Django application accepted any file type, served files back from the application's own origin, and made them reachable without authentication.

- An HTML file uploaded from a low-privileged student account was served as `text/html` and executed by the browser in the application's origin.
- The 5 MB limit shown in the interface was client-side only. A 10 MB file was accepted.
- `.py` and `.sh` files were accepted and served as static downloads, with no execution (section 9).

No injection into an existing page was shown. The uploaded file is its own document that happens to share the origin (section 3).

## 2. Overview

| Field | Details |
| --- | --- |
| Target | `redacted.example` |
| Application | Django-based coaching platform (nginx serving media) |
| Component | Student profile photo upload |
| Vulnerability | Unrestricted file upload, served from the application origin |
| Severity | Medium, CVSS 3.1 base score 5.4 |
| Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` |
| CWE | CWE-434, CWE-646. Related: CWE-79, CWE-770 (size limit) |
| OWASP | A04:2021, A05:2021 |
| Found / Reported | 2026-05-06 / 2026-05-12 |
| Researcher | `@EiV0id` |
| Status | Fixed by the owner after reporting |

## 3. Background

The application gives student accounts an editable profile with a photo upload. The upload is its own XHR endpoint, called from the profile page.

Two things stood out: the 5 MB limit existed only in the browser, and uploads came back from the application's own domain instead of a separate content host.

The second point matters more. A file at `https://redacted.example/media/profiles/...` shares scheme, host and port with `https://redacted.example/dashboard/...`, so the browser treats them as one trust boundary. Script inside an uploaded HTML file therefore runs with the application's origin privileges.

**This is not classic stored XSS.** The script does not run inside `/dashboard/my_profile/` or any server-rendered template. It runs in a separate document served from the same origin. CWE-79 is listed as related for that reason, not as primary.

## 4. Testing

Manual testing with Burp Suite from an authenticated student account. A legitimate upload was captured and replayed with the filename, part content-type and body varied.

| Uploaded | Result |
| --- | --- |
| Legitimate image | Accepted |
| HTML, heading only | Accepted, served as `text/html`, rendered |
| HTML with `image/png` part type | Accepted, served as `text/html`, rendered |
| HTML containing an inline script | Accepted, served as `text/html`, script executed |
| Python file | Accepted, served as download |
| Shell script | Accepted, served as download |
| 10 MB file against 5 MB limit | Accepted |

Served type followed the stored filename, not the declared part header. Public access was confirmed in a private window with no session.

The oversize file was random data generated locally and confirmed with `wc -c` before upload.

The supplied filename was kept as-is on first upload. Uploading the same name a second time did not overwrite it — Django's storage layer appended a random suffix instead, giving `pfp_zahwRwD.html`. That is collision handling, not validation: the extension survives untouched either way.

## 5. Reproduction

1. Sign in as a student and open the profile edit page.
2. Capture a legitimate photo upload.
3. Replace the file with an HTML document, keeping the request shape.
4. Read the returned URL from the response.
5. Request that URL with no session. It resolves.
6. The browser renders it as a page and the script runs.

Repeat steps 1 to 3 with a 10 MB body, and again with a `.py` file.

**Upload request (trimmed):**

```http
POST /dashboard/api/profile/upload-picture/ HTTP/1.1
Host: redacted.example
Cookie: csrftoken=<redacted>; sessionid=<redacted>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Referer: https://redacted.example/dashboard/my_profile/
X-Requested-With: XMLHttpRequest
X-Csrftoken: <redacted>
Content-Type: multipart/form-data; boundary=----X
Origin: https://redacted.example

------X
Content-Disposition: form-data; name="profile_pic"; filename="poc.html"
Content-Type: image/png

<!doctype html>
<html><body>
<h1>poc</h1>
<script>document.domain</script>
</body></html>
------X--
```

The part declares `image/png`, the filename is `.html`. The handler accepted it and served the file as `text/html`, so the served type came from the stored filename, not the declared header.

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"message": "Profile picture updated successfully.", "profile_pic": "https://redacted.example/media/profiles/pfp_zahwRwD.html"}
```

The random middle segment is from a repeat upload of the same filename.

**Retrieval:**

```http
GET /media/profiles/poc.html HTTP/1.1
Host: redacted.example
```

```http
HTTP/1.1 200 OK
Content-Type: text/html
```

The page rendered instead of downloading. Media is served by nginx directly, so the application's own headers do not apply to it.

**On the payload.** Several files were uploaded across the tests: a heading-only page, and a page containing an inline script. The script variant executed and printed the application's own domain into the page, confirming both execution and that the document is served from that host.

## 6. Impact

- Any student account can host arbitrary HTML on the organisation's trusted HTTPS domain, reachable without login.
- The uploaded document is served as `text/html` and script in it executes in the application's origin.

**Phishing on a domain users already trust.** An attacker can stand up a login clone at a `redacted.example` URL, which passes a casual link check, carries a valid certificate and shows a host users recognise. The page can be built to post straight to the real endpoint.

**Script with the victim's session behind it.** Because the document runs in the application's origin, same-origin requests carry the visitor's cookies automatically. Whatever that account can reach is reachable from the uploaded page, without the script ever needing to read a token.

**Free content hosting under the brand.** Arbitrary files can be stored and handed out from the domain with no authentication and no observed size cap, so `.py`, `.sh` or anything else can be distributed as a link that looks like part of the product.

## 7. Severity

**Medium: CVSS 3.1 base score 5.4**

| Metric | Value | Why |
| --- | --- | --- |
| Attack Vector | Network | Web application |
| Attack Complexity | Low | Nothing unusual needed |
| Privileges Required | Low | Student account |
| User Interaction | Required | Victim opens the link |
| Scope | Changed | Script runs in the origin and can act in other users' sessions |
| Confidentiality | Low | Same-origin reads possible, extent not measured |
| Integrity | Low | Limited to the victim's permissions |
| Availability | None | The size-limit bypass was not shown to affect availability |

The missing server-side size limit is tracked as a separate low-severity observation (CWE-770), not scored here.

CVSS has no metric for hosting attacker content on a trusted brand, which is the main practical cost here. Read the number as the technical floor, not the business risk.

## 8. Root Cause

Client-supplied metadata was trusted, and the result was served from the application's own origin.

| Control | Observed |
| --- | --- |
| Extension allowlist | Absent |
| Content inspection / image decoding | Absent |
| Server-side size limit | Absent |
| Random filenames | Only on collision |
| Separate content origin | Absent |

## 9. Related: non-executable uploads

`.py` and `.sh` files were accepted by the same handler and served as static downloads rather than executed. They are stored and delivered from the organisation's domain, so they serve as malware staging or file distribution. No server-side execution was obtained through them.

This is the same root cause and the same fix; it is split out only because the impact differs.

## 10. Remediation

**Validation.** Extension checks are spoofable and magic bytes can be forged, so neither is sufficient alone. Validation needs to combine an extension allowlist, content inspection and an actual decode by an image library, with the size limit enforced server-side on the received body.

**Storage.** Re-encode every accepted image so anything appended after the image data is dropped, and store under a random name with the extension taken from the decoded format.

**Delivery.** Serving user content from a separate origin is the real fix, since it removes the shared trust boundary entirely. Where that is not possible, the media path should send a download disposition for anything that is not a validated image, along with `nosniff`, and either a sandboxing CSP or one that blocks everything but images and inline styles. SVG is best rejected for avatars, since it can carry script.

**Limits.** A request body cap at the proxy, per-user quotas and upload rate limiting.

**Non-executable types.** If `.py` and `.sh` are kept, serve them as opaque binary with a download disposition so they are never guessed at.

## 11. Evidence

| # | File | Description |
| --- | --- | --- |
| 01 | `assets/01-upload-request.png` | Intercepted request, `.html` filename with `image/png` part type |
| 02 | `assets/02-rendered.png` | Plain HTML page hosted and rendered from the application origin |
| 03 | `assets/03-js-execution.png` | Script execution test — domain printed into the page |
| 04 | `assets/04-private-window.png` | Same URL in a private window, no session |
| 05 | `assets/05-size-limit.png` | 10 MB file accepted over the 5 MB interface limit |
| 06 | `assets/06-upload-response.png` | `200` response returning the public URL |
| 07 | `assets/07-py-download.png` | `.py` file served as a static download |

Domain, usernames, cookies and CSRF tokens are hidden.

## 12. Timeline

| Date | Event |
| --- | --- |
| 2026-05-06 | Vulnerability found |
| 2026-05-12 | Reported to the owner |
| 2026-06-05 | Report acknowledged |
| After 2026-06-05 | Fixed (exact date not recorded) |

The owner agreed to publication of this write-up.

## 13. Scope and Authorization

Testing was done with the owner's permission, using a low-privileged student account, limited to upload and retrieval. Only non-destructive content was uploaded, and the test files were removed afterwards. The issue was reported before publication.

## 14. Takeaway

Severity came from where the file was delivered, not from the fact that it was accepted. The same upload handler is far less serious when files are served from a separate origin with a download disposition. Check where a file lands first.

## References

- OWASP WSTG: File Upload Testing (WSTG-BUSL-08, WSTG-BUSL-09)
- CWE-434, CWE-646, CWE-79, CWE-770
- OWASP Top 10 2021: A04, A05
- FIRST CVSS 3.1 specification: https://www.first.org/cvss/v3.1/specification-document

*Independent research for educational and defensive purposes. Reported and remediated. Target identity and sensitive details redacted.*

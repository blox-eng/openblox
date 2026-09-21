# www — openblox.sh

The landing page: one screen, no scroll. Hand-written static HTML with no build
step and no dependencies — `index.html`, one stylesheet, one script, and the
marks and fonts it serves itself. Open `index.html` in a browser, or
`python3 -m http.server --directory www` for a server that resolves the root
path the way the host does.

`404.html` is served by Pages for any path that matches neither a file nor a
redirect. It carries **no script at all**: `app.js` drives the install tabs, the
copy button and the canvas, none of which exist on that page, and it reaches for
those elements without guarding — so including it would throw before the theme
handler ran, leaving a page whose toggle does nothing. The theme still follows
`prefers-color-scheme` through CSS, and the toggle persists nothing, so there is
no choice to carry across from the landing page in the first place. Inlining a
small script instead is not an option either: `_headers` sets `script-src 'self'`
with no `'unsafe-inline'`, and that is worth more than a toggle on an error page.

`install.sh` is served from here too, at the URL the page's own install command
prints. It is in the repository rather than pasted into a hosting dashboard so
that the script people are asked to pipe into a shell goes through the same
review and the same checks as everything else — and so "read it first", which
the page links, reaches something a reader can diff against its history.

The argument for openblox — the two-tier guarantee, the isolation-versus-
placement rule, what it does not do — lives in the documentation. This page's
job is to say what openblox is and get out of the way.

The reference documentation is a separate site — MkDocs, in `docs/`, deployed to
`docs.openblox.sh` by `.github/workflows/docs.yml`. This directory is not that
site and does not link into it by relative path.

## Deployment

Cloudflare Pages, connected to this repository. The domain is already on
Cloudflare, which is what makes apex support and the edge redirects free; GitHub
Pages could not serve both sites, because one repository gets one custom domain.

Connecting the project and repointing the apex are manual steps in the
Cloudflare dashboard, done once and not by anything in this repository. Until
they are, nothing here is served at `openblox.sh`. The settings to use:

| Setting | Value |
|---|---|
| Production branch | `main` |
| Build command | `.github/scripts/check-links.sh www` |
| Build output directory | `www` |
| Root directory | repository root |

The build command is a check, not a compiler: there is nothing to compile, and
the thing worth failing on is a reference that does not resolve. It is the same
script CI runs, so a broken link fails the preview deploy and the pull request
alike. Pages builds every pull request as its own preview URL.

`_redirects` and `_headers` are read by Pages and not served. The redirects
carry the documentation URLs that used to live on this apex over to
`docs.openblox.sh`, scoped to the documentation prefixes so they cannot swallow
this page.

## Fonts

IBM Plex Sans, Sans Condensed and Mono, latin subset, taken from the Google
Fonts CDN once and committed under `assets/fonts/`. They are served from this
origin rather than a font CDN, which is the honest position for a project about
not handing your workload to someone else. IBM Plex is licensed under the SIL
Open Font License 1.1, whose text ships alongside the files in
`assets/fonts/LICENSE.txt`.

## Analytics

Page counts come from Umami, which is cookieless and builds no cross-site
identity. It is the only third-party request the page makes, and the
Content-Security-Policy in `_headers` names its two hosts one directive at a
time — `cloud.umami.is` may script and may not post, `gateway.umami.is` may
post and may not script — so neither is allowed by accident.

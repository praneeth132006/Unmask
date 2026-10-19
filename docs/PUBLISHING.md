# Publishing Unmask to the browser stores

A simple, step-by-step guide to getting Unmask into the **Chrome Web Store**, **Firefox Add-ons** and **Microsoft Edge Add-ons**, so people can install it in one click. You only do the setup once; after that, updates take a few minutes.

**What you need first**

| | Chrome Web Store | Firefox Add-ons | Edge Add-ons |
|---|---|---|---|
| Account | A Google account | A Firefox (Mozilla) account | A Microsoft account |
| Cost | **US$5, one time** | Free | Free |
| Review time | Usually 1–3 days, longer for new developers | Hours to a few days | Up to 7 business days |
| File to upload | `unmask-chrome-<version>.zip` | `unmask-firefox-<version>.zip` + `unmask-extension-<version>-sources.zip` | `unmask-edge-<version>.zip` |

All the text and answers you'll be asked for are ready to copy in [STORE_LISTING.md](STORE_LISTING.md). Store-sized screenshots are in [`docs/store/`](store/).

---

## Step 0. Make the files

1. Make sure the version in `extension/package.json` is the one you want to publish (for example `0.3.0`), and that GitHub Actions is green.
2. In the project folder run:

   ```bash
   pnpm install
   pnpm zip:all
   ```

3. Open the `build/` folder. You'll find the three zips listed above plus the sources zip.

You can also take them from the **Assets** of a GitHub release: every release builds them automatically.

---

## Chrome Web Store (also covers Brave, Opera GX, Vivaldi and Arc users)

1. Go to the [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole) and sign in with your Google account.
2. Accept the developer agreement and **pay the one-time US$5 fee**. Turn on 2-step verification for the Google account if asked.
3. Fill in **Account**: publisher name (for example *Unmask*) and a contact email, and verify the email.
4. Click **New item** → upload `unmask-chrome-<version>.zip`.
5. **Store listing** tab:
   - Description: copy *Full description* from [STORE_LISTING.md](STORE_LISTING.md#2-listing-text-same-for-every-store).
   - Category: **Productivity**. Language: English.
   - Icon: `docs/brand/logo-512.png` is used from the zip automatically; upload a 128×128 if asked.
   - Screenshots: upload the 1280×800 images from `docs/store/` (at least 1, up to 5).
   - Small promo tile: `docs/store/promo-440x280.png`.
6. **Privacy** tab:
   - Single purpose: copy from STORE_LISTING.md section 3.
   - Permission justifications: copy each line from the table in section 4.
   - Remote code: **No**.
   - Data usage: tick nothing, then tick the three certifications at the bottom.
   - Privacy policy URL: `https://praneeth132006.github.io/Unmask/privacy.html`
7. **Distribution** tab: Public, all regions.
8. Click **Submit for review**. You'll get an email when it's approved; the store page link appears in the dashboard.

**Updating later:** dashboard → Unmask → **Package** → *Upload new package* → **Submit for review**. Or run the *Publish to stores* GitHub workflow (see the end of this guide).

---

## Firefox Add-ons (addons.mozilla.org)

1. Go to the [Firefox Add-on Developer Hub](https://addons.mozilla.org/developers/) and sign in or create a Firefox account. It's free.
2. Click **Submit a New Add-on**.
3. Choose **On this site** (listed publicly on addons.mozilla.org).
4. Upload `unmask-firefox-<version>.zip`. Mozilla's checker runs automatically; Unmask passes with no errors (two warnings about React's own code are normal).
5. When asked **"Do you need to submit source code?"** choose **Yes** and upload `unmask-extension-<version>-sources.zip`. Mozilla needs it because the code is bundled and minified. In *Notes to reviewer*, paste the reviewer notes from STORE_LISTING.md section 5.
6. Describe the add-on: name, summary, description (from STORE_LISTING.md), category **Privacy & Security**, support site `https://github.com/praneeth132006/Unmask`, license **MIT**, privacy policy (paste the text of `PRIVACY.md` or link to it).
7. Add screenshots from `docs/store/`.
8. Click **Submit Version**. You'll get an email after review.

**Updating later:** Developer Hub → Unmask → **Upload New Version** → same steps 4–5.

Note: Firefox lets users decide whether an extension may run on a site. After installing, users may need to click the Unmask icon or the puzzle-piece menu and allow it on Gmail and Outlook. The user guide explains this.

---

## Microsoft Edge Add-ons

1. Go to [Partner Center](https://partner.microsoft.com/dashboard/microsoftedge/public/login) and sign in with a Microsoft account (a personal Outlook/Hotmail account works).
2. Register for the **Microsoft Edge** program. It's free: fill in your name, email and country, and accept the agreement.
3. Click **Create new extension** → upload `unmask-edge-<version>.zip`.
4. **Availability**: Public, all markets.
5. **Properties**: category **Productivity**, privacy policy URL `https://praneeth132006.github.io/Unmask/privacy.html`, website `https://praneeth132006.github.io/Unmask/`, support `https://github.com/praneeth132006/Unmask/issues`.
6. **Store listings** → English: description and short description from STORE_LISTING.md, the 300×300 logo (`docs/brand/logo-512.png` resized), and screenshots from `docs/store/`.
7. **Submission options** → *Notes for certification*: paste the reviewer notes.
8. Click **Publish**. Certification can take up to 7 business days.

**Updating later:** Partner Center → Unmask → **Packages** → *Replace* → **Publish**.

---

## Other browsers

- **Brave, Vivaldi, Arc, Opera GX, Chromium:** they install from the Chrome Web Store. Nothing extra to do.
- **Opera:** has its own store at [addons.opera.com/developer](https://addons.opera.com/developer/), free. Upload the Chrome zip.
- **Safari:** needs an Apple Developer account (US$99 a year), a Mac with Xcode, and converting the extension with `xcrun safari-web-extension-converter build/unmask-chrome`. Gmail-in-Safari users are a small share, so this can wait.

---

## After the first approval: automatic updates

1. Add the store keys to GitHub: **Settings → Secrets and variables → Actions → New repository secret**. The exact names and where to get each key are in [STORE_LISTING.md section 6](STORE_LISTING.md#6-automatic-publishing).
2. When you release a new version: bump the version, tag it (`git tag v0.3.0 && git push --tags`), wait for the release to build.
3. Go to **Actions → Publish to stores → Run workflow**. Run it first with *dry run* ticked to check the keys, then again without it.

Each store still reviews every update, so it won't be live instantly.

---

## Checklist before every submission

- [ ] GitHub Actions is green on `main`
- [ ] Version bumped in `extension/package.json` and a `CHANGELOG.md` entry written
- [ ] Tested the built extension: Gmail email with a risky link shows the banner and the "Wait" dialog
- [ ] `PRIVACY.md` still describes everything the extension sends
- [ ] Screenshots in `docs/store/` are current (`node extension/scripts/screenshots.mjs`)

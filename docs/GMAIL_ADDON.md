# Unmask for Gmail (Google Workspace add-on)

The add-on puts Unmask inside Gmail on the web **and in the Gmail apps for Android and iPhone**, where browser extensions can't run. Open an email and Unmask's card shows the verdict, the reasons in plain words, what to do and the red flags, each linked to a lesson.

## How it keeps your email private

The add-on runs in Google's Apps Script runtime **inside the user's own Google account**. It asks for two permissions only:

- `gmail.addons.execute`: to run as a Gmail add-on.
- `gmail.addons.current.message.readonly`: to read **only the message that is open**, only while it is open.

The message is checked by the same engine as the extension and never sent to an Unmask server (there is none). It has no network access to anything else.

## Build and test

```bash
pnpm gmail-addon
```

This builds `gmail-addon/dist` (Engine.js, Code.js, appsscript.json) and runs the engine in a bare JavaScript sandbox with a stand-in for Apps Script's `Utilities`, the same way Apps Script runs it, on two real phishing samples and one real email.

## Publish it (you do this once, from your Google account)

1. Install clasp and sign in: `npm i -g @google/clasp` then `clasp login`.
2. Create the project: `cd gmail-addon/dist && clasp create --type standalone --title "Unmask"`, then `clasp push`.
3. Try it on your own account: in the Apps Script editor, **Deploy → Test deployments → Install**, then open Gmail on the web and on your phone.
4. Link a Google Cloud project (Project Settings → change project), configure the **OAuth consent screen** with the privacy policy `https://praneeth132006.github.io/Unmask/privacy.html`.
5. Enable the **Google Workspace Marketplace SDK**, fill in the store listing (texts below), and submit for review. Google reviews the OAuth scopes and the listing; public apps usually take a few weeks.

### Listing texts

- **Name:** Unmask
- **Short description:** See what a suspicious email is really hiding, right inside Gmail.
- **Long description:** Unmask checks the email you open for phishing: who really sent it, where its links go, look-alike domains, pressure tricks and hidden text. It explains the verdict in plain words and tells you what to do. Everything is checked inside your own Google account; nothing is sent to Unmask, and there are no accounts, ads or tracking. Free and open source.
- **Support:** https://github.com/praneeth132006/Unmask/issues · **Privacy:** https://praneeth132006.github.io/Unmask/privacy.html

## Status

Built and tested in a simulated Apps Script runtime. **Not yet run in real Apps Script or published**: that needs the steps above from the project owner's Google account. Attachments aren't opened in the add-on yet.

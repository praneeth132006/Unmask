# Unmask for Outlook (add-in) and Microsoft AppSource

The add-in adds **Check with Unmask** to Outlook on the web, Windows, Mac and the **Outlook apps for iPhone and Android**. It reads the open message through Outlook's add-in API (`ReadItem` permission) and checks it in the add-in pane with the same engine as the extension. Nothing is sent to any server.

- Manifest: [`site/outlook/manifest.xml`](../site/outlook/manifest.xml), published at `https://praneeth132006.github.io/Unmask/outlook/manifest.xml`
- Task pane: `https://praneeth132006.github.io/Unmask/outlook/taskpane.html`

## Try it now (sideload)

Outlook on the web → **Get add-ins → My add-ins → Add a custom add-in → Add from URL**, paste the manifest address. It then also appears in Outlook mobile for the same account.

## Get it listed on AppSource (yes, you can apply)

Listing is free. It needs a Microsoft account of your own, so these steps are yours to do:

1. **Validate the manifest** with Microsoft's tool: `npx office-addin-manifest validate site/outlook/manifest.xml` (fix anything it reports).
2. **Join the Microsoft AI Cloud Partner Program** and open **Partner Center → Marketplace offers → Office add-in** (individual developers can enrol; it asks for identity verification).
3. **Create an "Office add-in" offer**, upload the manifest, and fill in the listing:
   - **Name:** Unmask · **Category:** Security, Productivity
   - **Summary:** See what a suspicious email is really hiding.
   - **Description:** Unmask checks the email you open for phishing: who really sent it, where its links go, look-alike domains, pressure tricks and hidden text, and explains the verdict in plain words with what to do. Everything is checked inside the add-in on your device; nothing is sent to Unmask, and there are no accounts, ads or tracking. Free and open source.
   - **Privacy policy:** https://praneeth132006.github.io/Unmask/privacy.html
   - **Support:** https://github.com/praneeth132006/Unmask/issues
   - **End-user licence:** the standard Microsoft contract, or https://github.com/praneeth132006/Unmask/blob/main/LICENSE
   - **Icons:** `site/media/icon-64.png`, `site/media/icon-128.png` · **Screenshots (1366×768):** take them in Outlook on the web after sideloading.
   - **Test notes:** "Open any email and press Check with Unmask in the message toolbar (on mobile: the ⋯ menu). No sign-in or test account is needed."
4. **Submit.** Microsoft tests the add-in on every platform the manifest declares (web, Windows, Mac, iOS, Android). Mobile support is checked carefully: test it on your phone first. Review usually takes 3–5 business days, and they send a report if anything fails.

## Status

Built and served by the website. Not yet validated with Microsoft's tool, run in a real Outlook account, or submitted: those need your Microsoft account.

# Unmask for teams, schools and families

Unmask is free for organisations too. There is no paid tier and no account. Everything below uses tools your organisation already has.

| You are | Use |
|---|---|
| A family or a small team without an IT admin | [Share the list as a file](#share-the-list-as-a-file) |
| An IT admin with Google Admin, Group Policy, Intune or a Mac profile | [Install it everywhere and push the list by policy](#install-it-for-everyone-and-push-the-list) |

## What a team gets

- **One protection list for everyone.** Your payroll provider's real domain, your CEO's real addresses, your bank, your trusted vendors. An email imitating any of them gets the strongest red warning on every computer.
- **Nothing to set up for each person.** The admin's list appears in Settings as "From your organisation", read-only. People can still add their own entries next to it.
- **The same privacy.** Unmask still sends nothing to us and keeps no central log. The admin pushes the list *to* browsers; nothing comes back.

## Share the list as a file

1. One person fills in **Settings → Your protection list**.
2. They click **Export list**, which saves `unmask-protection.json`.
3. Everyone else clicks **Import list** and picks that file. Importing only adds; it never removes anything.

Repeat the export when the list changes.

## Install it for everyone and push the list

The policy value is the same JSON as an exported `unmask-protection.json`:

```json
{
  "label": "Acme IT",
  "brands": [
    { "name": "Acme Payroll", "domains": ["acmepayroll.com"] },
    { "name": "HDFC Bank", "domains": ["hdfcbank.com", "hdfcbank.net"] }
  ],
  "contacts": [
    { "name": "Priya Menon", "addresses": ["priya@acme.com", "priya.menon@acme.com"] }
  ],
  "trusted": ["acme.com", "billing@vendor.example"]
}
```

`label` is shown to users ("From “Acme IT”"). Entries that aren't valid (a brand with no domain, a malformed address) are skipped.

**Extension IDs**
- Chrome and Edge (from the Chrome Web Store): `bcogajaabcenbcbfbcgfjmccjdlfklcc`
- Firefox: `unmask@praneeth132006.github.io`

### Google Admin console (Chrome Enterprise, Google Workspace)

1. **Devices → Chrome → Apps & extensions → Users & browsers**, pick the organisational unit.
2. Add a Chrome app or extension by ID: `bcogajaabcenbcbfbcgfjmccjdlfklcc`.
3. Set **Installation policy** to **Force install** (or **Force install + pin to browser toolbar**).
4. In **Policy for extensions**, paste the list wrapped under `protectionList` with a `Value`:

```json
{ "protectionList": { "Value": { "label": "Acme IT", "brands": [], "contacts": [], "trusted": ["acme.com"] } } }
```

### Windows: Group Policy or Intune (Chrome and Edge)

Force-install with the `ExtensionInstallForcelist` policy:

```
bcogajaabcenbcbfbcgfjmccjdlfklcc;https://clients2.google.com/service/update2/crx
```

Push the list as a registry value of type `REG_SZ` named `protectionList`, holding the JSON above on one line:

- Chrome: `HKLM\Software\Policies\Google\Chrome\3rdparty\extensions\bcogajaabcenbcbfbcgfjmccjdlfklcc\policy`
- Edge: `HKLM\Software\Policies\Microsoft\Edge\3rdparty\extensions\bcogajaabcenbcbfbcgfjmccjdlfklcc\policy`

In Intune, deploy the same settings with the Chrome or Edge administrative templates, or a custom OMA-URI.

### macOS: configuration profile

Use a profile with the payload domain `com.google.Chrome.extensions.bcogajaabcenbcbfbcgfjmccjdlfklcc` and a dictionary key `protectionList` holding the list (as a dictionary, not a string).

### Firefox: policies.json

```json
{
  "policies": {
    "ExtensionSettings": {
      "unmask@praneeth132006.github.io": {
        "installation_mode": "force_installed",
        "install_url": "https://addons.mozilla.org/firefox/downloads/latest/unmask-phishing-inspector/latest.xpi"
      }
    },
    "3rdparty": {
      "Extensions": {
        "unmask@praneeth132006.github.io": {
          "protectionList": { "label": "Acme IT", "brands": [], "contacts": [], "trusted": ["acme.com"] }
        }
      }
    }
  }
}
```

### Check that it worked

Open Unmask → **Settings**. The protection list starts with **From “Acme IT”** and the entries you pushed. In Chrome, `chrome://policy` also lists the extension's policy.

## Online checks at work

Every check that runs on the computer needs no key and no account: sender, links, look-alike domains, attachments, QR codes, tracking pixels, your protection list. That's most of Unmask, and it's free for any use.

The optional buttons for outside services follow those services' own rules:

- **VirusTotal's free API is for personal use only.** In a business it needs a VirusTotal Premium licence. Without one, leave the VirusTotal key empty on work computers; Unmask works fine without it.
- **urlscan.io, Hybrid Analysis and abuse.ch** each have their own terms for organisations. Check them before rolling keys out.

See [Limits & costs](LIMITS_AND_COSTS.md) for the details of each service.

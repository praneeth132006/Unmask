# Unmask for Safari (macOS and iOS)

Unmask builds for Safari from the same code. Safari has no side panel, so the report opens from the toolbar button as a popup, and the analysis runs in the background page (as in Firefox) instead of an offscreen document.

## Build it

```bash
pnpm --filter unmask-extension build:safari     # build/unmask-safari
pnpm --filter unmask-extension safari:xcode     # build/safari-xcode, an Xcode project for macOS and iOS
```

`safari:xcode` needs full Xcode (not just the command-line tools), because it runs Apple's `safari-web-extension-converter`. Open the project in Xcode, pick the macOS or iOS target, and run it. In Safari, turn on **Settings → Advanced → Show features for web developers**, then **Develop → Allow Unsigned Extensions** to try an unsigned build.

## What differs from Chrome

- **No side panel:** the toolbar button opens the report as a popup. Buttons inside Gmail that open the panel in Chrome do nothing in Safari yet; use the toolbar button.
- **No admin policy list:** Safari has no managed storage, so a protection list pushed by IT policy isn't read. Importing a list file still works.
- **Not yet tested on a device:** the build and its manifest are checked, but no one has run it in Safari yet. Please [report what you find](https://github.com/praneeth132006/Unmask/issues/new/choose).

Publishing to the App Store needs an Apple Developer account and is not done yet.

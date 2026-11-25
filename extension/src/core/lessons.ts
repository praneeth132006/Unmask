/**
 * "How this trick works": a short lesson for each kind of red flag, shown on
 * the website (lessons.html) and linked from every matching finding in the
 * panel. Plain words first; no lesson needs technical knowledge.
 *
 * `match` lists finding ids, or id prefixes ending in '-' (e.g. 'landing-fake-login-').
 */
export interface Lesson {
  id: string;
  title: string;
  /** One line: the trick in a sentence. */
  summary: string;
  how: string;
  spot: string[];
  todo: string;
  match: string[];
}

export const LESSONS: Lesson[] = [
  {
    id: 'look-alike-domains',
    title: 'Look-alike addresses',
    summary: 'paypa1.com is not paypal.com: one swapped letter is enough to fool a quick look.',
    how: 'Scammers register addresses that look like a real company: a 1 for an l, rn for m, an extra word ("paypal-support"), or letters from other alphabets that look identical. The email and its links then use that address.',
    spot: ['Read the part just before .com (or .co.uk, .in…) letter by letter.', 'Extra words like -secure, -support, -verify are a warning sign.', 'Hover a link: the address that appears is where it really goes.'],
    todo: 'Don’t use the link. Type the company’s address yourself or use its app.',
    match: ['sender-lookalike', 'protected-lookalike', 'protected-link-lookalike', 'mixed-script-text', 'link-lookalike', 'link-punycode', 'link-confusable'],
  },
  {
    id: 'brand-impersonation',
    title: 'Pretending to be a company',
    summary: 'A familiar name and logo, sent from an address the company doesn’t use.',
    how: 'Anyone can type "PayPal Service" as their display name and paste PayPal’s logo into an email. What they can’t fake is sending from paypal.com when the company protects it, so they send from somewhere else and hope you only read the name.',
    spot: ['Look at the address after the name, not just the name.', 'A real company writes from its own domain, not Gmail or a random site.', 'Logos prove nothing: they are just pictures.'],
    todo: 'Go to the company’s site or app yourself to check if anything is wrong with your account.',
    match: ['brand-impersonation', 'protected-brand', 'display-name-email', 'fake-logo-', 'freemail-org', 'bimi-', 'history-brand-mismatch'],
  },
  {
    id: 'link-text-mismatch',
    title: 'Links that show one address and go to another',
    summary: 'The text says paypal.com; the link underneath goes somewhere else.',
    how: 'In an email, the words you see and the address a link opens are two separate things. Scammers write a trusted address as the text, and point the link at their own site. Redirect services and link shorteners hide the destination further.',
    spot: ['Hover the link (or long-press on a phone) and read where it really goes.', 'Short links (bit.ly and similar) hide their destination.', 'A link that goes through Google or another redirect first is hiding where it ends.'],
    todo: 'Don’t click. If you need the site, type its address yourself.',
    match: ['link-text-mismatch', 'link-shortener', 'link-redirect', 'link-encoded-href', 'link-tracker-mismatch', 'link-ip-host', 'link-odd-port', 'link-suspicious-tld', 'link-abused-host', 'link-'],
  },
  {
    id: 'fake-sign-in-pages',
    title: 'Fake sign-in pages',
    summary: 'A page that looks exactly like Microsoft, Google or your bank, and sends your password to the scammer.',
    how: 'The link leads to a copy of a real sign-in page. Some are plain copies; others relay what you type to the real site in real time, so they can pass two-step codes too. Many hide behind a CAPTCHA so security scanners can’t see them.',
    spot: ['Check the address bar before typing a password: it must be the company’s real domain.', 'A CAPTCHA before a sign-in page is unusual.', 'Your password manager not filling in is a strong warning.'],
    todo: 'Close the page. If you typed a password, change it on the real site and sign out of other sessions.',
    match: ['landing-fake-login-', 'landing-relay-', 'landing-captcha-', 'html-form', 'credential-request', 'markup-captcha'],
  },
  {
    id: 'sender-authentication',
    title: 'Who really sent it (SPF, DKIM, DMARC)',
    summary: 'The address on an email can be forged; these checks show whether the sender is who it claims.',
    how: 'SPF lists which servers may send for a domain, DKIM is a signature only the real domain can make, and DMARC tells receivers what to do when both fail. A failing check means the email may not be from where it says. A passing check only proves who sent it: scammers pass easily on domains they own.',
    spot: ['“Not verified” on a famous brand is a red flag.', 'A pass from a domain you don’t recognise means nothing about safety.'],
    todo: 'Treat a failed check on a well-known company as a fake.',
    match: ['spf-fail', 'spf-softfail', 'spf-none', 'spf-neutral-', 'spf-open-', 'dkim-fail', 'dkim-none', 'dkim-unaligned', 'dmarc-fail', 'dmarc-none-', 'auth-missing', 'auth-results-forged', 'webmail-forged', 'trusted-spoof'],
  },
  {
    id: 'replayed-emails',
    title: 'Real emails, sent again by someone else',
    summary: 'A genuine, signed email from Google or PayPal, forwarded with the scammer’s text inside.',
    how: 'Some services let anyone put their own words into a real notification (a shared document title, an invoice note, an organisation name). The email is genuinely from the company and passes every check, but the message inside is the scammer’s. Others record a real signed email and resend it to thousands of people.',
    spot: ['A real notification whose content asks you to call a number or pay.', 'Sent to an address that isn’t yours, or to “undisclosed recipients”.'],
    todo: 'Judge what it asks you to do, not who sent it. Never call numbers inside notifications.',
    match: ['dkim-replay', 'replay-addressee', 'dkim-body-altered', 'dkim-partial-body', 'dkim-added-', 'platform-abuse', 'arc-broken'],
  },
  {
    id: 'reply-to-tricks',
    title: 'Replies that go somewhere else',
    summary: 'The email comes from one address, but your reply goes to the scammer.',
    how: 'An email can say “reply to this other address”. Scammers use it so the conversation leaves the real company, or so the real person you think you’re writing to never sees your answer.',
    spot: ['Before replying, check the “To” line of your reply.', 'A reply address on Gmail or Outlook.com for a company email.'],
    todo: 'Start a new email to the address you already know, instead of pressing Reply.',
    match: ['reply-to-mismatch', 'return-path-mismatch', 'dkim-reply-to-unsigned', 'fake-reply', 'multiple-from'],
  },
  {
    id: 'urgency',
    title: 'Pressure and deadlines',
    summary: '“Within 24 hours or your account is closed.” Panic stops you checking.',
    how: 'Almost every scam adds a deadline, a threat or a prize. Real companies rarely close accounts by email with a few hours’ notice. The aim is to make you act before you think.',
    spot: ['A short deadline, a threat to close an account, or a reward that expires.', 'Words like urgent, immediately, final notice, suspended.'],
    todo: 'Slow down. Check through the official app or a number you already have.',
    match: ['urgency', 'money-lure'],
  },
  {
    id: 'payment-fraud',
    title: 'Changed bank details and gift cards',
    summary: 'A supplier’s or boss’s “new account”, or a quick request for gift cards.',
    how: 'Business email compromise: the scammer pretends to be a supplier, colleague or boss and asks to pay to a new account, or to buy gift cards “for a client”. They often use a real hacked account or a look-alike one, and write in a calm, normal tone.',
    spot: ['Any change of bank details by email.', 'Gift cards for work are always a scam.', 'Requests to keep it quiet or to skip the usual approval.'],
    todo: 'Call the person on a number you already have before paying anything.',
    match: ['bec-bank-change', 'bec-gift-card', 'bec-pattern', 'bec-payment', 'bec-pretext', 'contact-impersonation', 'protected-contact'],
  },
  {
    id: 'callback-scams',
    title: 'Call-this-number scams',
    summary: 'No link at all: an “invoice” for something you didn’t buy, and a number to cancel.',
    how: 'The email has nothing to click, so filters let it through. When you call to cancel, a “support agent” asks you to install remote-access software or to confirm card details.',
    spot: ['An invoice or renewal you don’t recognise, with a phone number to call.', 'Geek Squad, Norton, McAfee or PayPal “orders” are the usual names.'],
    todo: 'Don’t call. Check your real account or bank statement yourself.',
    match: ['callback-phishing', 'calendar-callback'],
  },
  {
    id: 'qr-codes',
    title: 'QR codes',
    summary: 'A QR code moves the link to your phone, where it’s harder to check and security tools don’t see it.',
    how: 'Scammers put a QR code in the email or a PDF (“scan to keep your account”). Your phone opens the link, away from your computer’s protections, and phones show less of the address.',
    spot: ['A QR code in an email asking you to sign in or pay.', 'Unmask shows where each QR code goes, without scanning it.'],
    todo: 'Don’t scan QR codes from emails for anything to do with passwords or payments.',
    match: ['qr-code'],
  },
  {
    id: 'dangerous-attachments',
    title: 'Dangerous attachments',
    summary: '“Invoice.pdf.html” is a web page, not a PDF. Some files run programs when opened.',
    how: 'Files can hide what they are: a double extension, an HTML page that shows a fake sign-in, an Office document with macros, a PDF with links or scripts, or a ZIP with a program inside and the password in the email so scanners can’t look.',
    spot: ['Two extensions in a name (.pdf.html, .doc.exe).', 'A ZIP with its password written in the email.', '“Enable content” or “Enable editing” prompts in Office.'],
    todo: 'Don’t open files you didn’t expect. Ask the sender another way.',
    match: ['attachment-', 'disguised-', 'type-mismatch', 'program-content', 'office-macros', 'office-', 'pdf-javascript', 'pdf-', 'ole-', 'rtf-', 'lnk-file', 'archive-password-in-body', 'archive-unreadable', 'script-commands', 'script-hidden-program'],
  },
  {
    id: 'svg-and-html-smuggling',
    title: 'Pictures and pages that run code',
    summary: 'An SVG “image” or an HTML attachment that builds a fake page or download inside your browser.',
    how: 'SVG images can carry scripts, and HTML attachments can assemble a file or a sign-in page right on your computer, so nothing suspicious ever crosses the network for a filter to block.',
    spot: ['An .svg or .html attachment from a stranger, especially “a voicemail” or “a document”.'],
    todo: 'Don’t open it. Real documents don’t arrive as .svg files.',
    match: ['svg-script', 'svg-embedded-page', 'markup-smuggling', 'markup-script-link', 'markup-redirect', 'markup-event-handler', 'markup-hidden-payload', 'html-script'],
  },
  {
    id: 'hidden-text',
    title: 'Hidden and disguised text',
    summary: 'White-on-white words, invisible characters and coded letters, written for spam filters, not for you.',
    how: 'Scammers hide innocent text to make spam filters score the email as safe, break up brand names with invisible characters so filters can’t read them, or write words as HTML codes. You see a normal email; the filter sees something else.',
    spot: ['Unmask’s Body tab reveals the hidden text.'],
    todo: 'An email that hides things from filters is not to be trusted.',
    match: ['hidden-text', 'invisible-splitters', 'entity-encoded-text', 'image-only', 'high-entropy'],
  },
  {
    id: 'clickfix',
    title: 'Fake CAPTCHAs that ask you to paste a command',
    summary: '“Press Windows+R, then Ctrl+V, then Enter to prove you’re human.” This installs malware.',
    how: 'A fake verification page copies a command to your clipboard and asks you to paste it into the Run box or a terminal. You run the scammer’s program yourself, so security software doesn’t step in.',
    spot: ['Any website asking you to press Windows+R, open Terminal or paste something.'],
    todo: 'Never do it. Close the page.',
    match: ['clickfix', 'clickfix-attachment-'],
  },
  {
    id: 'device-code-and-consent',
    title: 'Real Microsoft pages that still give your account away',
    summary: 'A code to type on microsoft.com/devicelogin, or an app asking for permission to your mail.',
    how: 'The page is real, so it looks perfectly safe. But typing the scammer’s code, or approving their app, signs their device or app into your account. No password is needed.',
    spot: ['An email giving you a code to enter, when you didn’t start a sign-in.', 'A permission screen for an app you don’t know asking to read your mail.'],
    todo: 'Only enter codes you asked for yourself. Decline unknown app permissions.',
    match: ['device-code-lure', 'oauth-consent-link'],
  },
  {
    id: 'fake-jobs',
    title: 'Fake jobs and task scams',
    summary: '“Rate products online, $300 a day, no interview, contact us on Telegram.”',
    how: 'You’re paid small amounts for easy tasks to build trust, then asked to “top up” your account to unlock bigger tasks. Or you’re sent a cheque to buy equipment and asked to return the difference before it bounces.',
    spot: ['No interview, high pay for simple tasks, a move to Telegram or WhatsApp.', 'Being asked to pay anything to get a job.'],
    todo: 'Real employers never ask you to pay. Stop replying.',
    match: ['job-scam'],
  },
  {
    id: 'calendar-invites',
    title: 'Calendar-invite phishing',
    summary: 'A meeting invite with a fake “join” link, which can stay in your calendar after you delete the email.',
    how: 'Invites get added to your calendar automatically, so the lure keeps reminding you. The “join” link goes to a fake sign-in, or the event asks you to call a number about payroll or benefits.',
    spot: ['An invite from someone you don’t know about payroll, bonuses or HR.', 'A join link that isn’t Zoom, Teams or Google Meet.'],
    todo: 'Delete the event from your calendar too, without opening its link.',
    match: ['calendar-lure', 'calendar-odd-link', 'calendar-organizer-mismatch', 'calendar-outside-link'],
  },
  {
    id: 'hacked-contacts',
    title: 'Messages from a friend’s hacked account',
    summary: 'A real friend or colleague, writing in an unusual way: often “I shared a document with you”.',
    how: 'Once a scammer controls a real account, everything checks out: the address, the signature, the history. They send the same lure to everyone in the contacts, often at odd hours.',
    spot: ['A first-ever link or document from someone who never sends you files.', 'A different writing style, odd hours, or a vague subject.'],
    todo: 'Message the person another way to ask if they really sent it.',
    match: ['contact-first-link', 'fingerprint-changed', 'first-contact'],
  },
  {
    id: 'trackers',
    title: 'Tracking pixels',
    summary: 'Tiny invisible images that tell the sender when, where and on what device you opened the email.',
    how: 'Loading a 1×1 image from the sender’s server reports that you opened the email. Scammers use it to find live addresses worth targeting again.',
    spot: ['Unmask lists each tracker and where it sits.'],
    todo: 'Use Peek to read emails without loading their images.',
    match: ['tracking-pixel', 'tracked-links'],
  },
  {
    id: 'delivery-path',
    title: 'Odd delivery paths',
    summary: 'Sent from a home connection, a rented server or a script instead of a company mail system.',
    how: 'Every email records the servers it passed through. Large companies send from their own mail systems. A message claiming to be from a bank that left a home internet connection, a rented server or a PHP script is almost certainly not from the bank.',
    spot: ['Unmask’s Headers tab reads the path for you.'],
    todo: 'Use it as one more clue, together with the others.',
    match: ['received-', 'ip-home-connection', 'ip-rented-server', 'ip-ptr-unconfirmed', 'mailer-script', 'mailer-spam-tool', 'message-id-missing', 'date-future', 'date-old', 'mail-records-'],
  },
];

/** The lesson for a finding id, if any. Exact ids win over prefixes; longer prefixes over shorter ones. */
export function lessonFor(findingId: string): Lesson | null {
  let best: { lesson: Lesson; len: number } | null = null;
  for (const lesson of LESSONS) {
    for (const m of lesson.match) {
      const hit = m.endsWith('-') ? findingId.startsWith(m) : findingId === m || findingId.startsWith(`${m}-`);
      if (!hit) continue;
      const len = m.endsWith('-') ? m.length : 1000 + m.length;
      if (!best || len > best.len) best = { lesson, len };
    }
  }
  return best?.lesson ?? null;
}

export const LESSONS_URL = 'https://praneeth132006.github.io/Unmask/lessons.html';

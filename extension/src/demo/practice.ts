/**
 * Practice mode: realistic made-up emails (the labelled test corpus), each with one lesson.
 * Shown as text only; nothing in them can be clicked.
 */
export interface PracticeItem {
  id: string;
  scam: boolean;
  raw: string;
  lesson: string;
}

export const PRACTICE: PracticeItem[] = [
 {
  "id": "ceo-gift-cards-gmail",
  "scam": true,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Mon, 19 Oct 2026 16:00:06 +0000\nReceived: from vps-3381.hostserv.example (unknown [203.0.113.77])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Mon, 19 Oct 2026 16:00:05 +0000\nAuthentication-Results: mx.google.com;\n       spf=softfail (google.com: domain of transitioning daniel.reyes.ceo@gmail.com does not designate 203.0.113.77 as permitted sender) smtp.mailfrom=daniel.reyes.ceo@gmail.com;\n       dmarc=fail (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com\nFrom: \"Daniel Reyes (CEO)\" <daniel.reyes.ceo@gmail.com>\nTo: alex.morgan@example.org\nSubject: Quick task\nDate: Mon, 19 Oct 2026 16:00:00 +0000\nMessage-ID: <20261019160000.4471@vps-3381.hostserv.example>\nX-Mailer: PHPMailer 6.8.0\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nAlex, are you available? I am in a meeting and need you to buy 5 Apple gift cards ($200 each) for a client today. Keep this confidential. Scratch the back and send me the codes by email.\nDaniel\n",
  "lesson": "Your boss writing from a personal Gmail and asking for gift cards is always a scam. Call them on a number you already have."
 },
 {
  "id": "fake-reply-bank-change",
  "scam": true,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Mon, 19 Oct 2026 16:00:06 +0000\nReceived: from mail.acme-supp1y.com (mail.acme-supp1y.com [198.51.100.88])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Mon, 19 Oct 2026 16:00:05 +0000\nAuthentication-Results: mx.google.com;\n       dkim=pass header.i=@acme-supp1y.com;\n       spf=pass smtp.mailfrom=acme-supp1y.com;\n       dmarc=pass (p=NONE) header.from=acme-supp1y.com\nFrom: \"Maria Chen, Acme Supply\" <maria.chen@acme-supp1y.com>\nReply-To: maria.chen.acme@outlook.com\nTo: alex.morgan@example.org\nSubject: RE: Invoice 7781 payment\nDate: Mon, 19 Oct 2026 16:00:00 +0000\nMessage-ID: <b1@acme-supp1y.com>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nHi Alex,\nFollowing up on the invoice below. Please note our bank details have changed due to an audit. Kindly send this payment by wire transfer to our new account:\nIBAN: GB33 BUKB 2020 1555 5555 55, SWIFT BUKBGB22.\nPlease treat this as urgent and confidential.\nMaria\n",
  "lesson": "\"RE:\" and an invoice number make it look like an old conversation. A sudden change of bank details must be checked by phone."
 },
 {
  "id": "geek-squad-renewal-callback",
  "scam": true,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Mon, 19 Oct 2026 16:00:06 +0000\nReceived: from mail-sor-f69.google.com (mail-sor-f69.google.com [209.85.220.69])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Mon, 19 Oct 2026 16:00:05 +0000\nAuthentication-Results: mx.google.com;\n       dkim=pass header.i=@gmail.com;\n       spf=pass smtp.mailfrom=billing.protection.desk@gmail.com;\n       dmarc=pass (p=NONE) header.from=gmail.com\nFrom: \"Geek Squad Billing\" <billing.protection.desk@gmail.com>\nTo: alex.morgan@example.org\nSubject: Order Confirmation #GS-88271\nDate: Mon, 19 Oct 2026 16:00:00 +0000\nMessage-ID: <CAH+wq3r=ab@mail.gmail.com>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nThank you for renewing your Geek Squad Total Protection. Your account will be charged $399.99 today for the annual auto-renewal.\nIf you did not make this purchase or want to cancel, please call our billing department at 1-808-555-0142 within 24 hours for a full refund.\n",
  "lesson": "No link to click: the scam happens on the phone. Never call a number from an unexpected invoice; look it up yourself."
 },
 {
  "id": "docusign-lookalike-prefilled",
  "scam": true,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Mon, 19 Oct 2026 16:00:06 +0000\nReceived: from mail.docusign-secure-review.net (mail.docusign-secure-review.net [198.51.100.23])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Mon, 19 Oct 2026 16:00:05 +0000\nAuthentication-Results: mx.google.com;\n       dkim=pass header.i=@docusign-secure-review.net;\n       spf=pass smtp.mailfrom=docusign-secure-review.net;\n       dmarc=pass (p=NONE) header.from=docusign-secure-review.net\nFrom: \"DocuSign\" <dse@docusign-secure-review.net>\nTo: alex.morgan@example.org\nSubject: Please review and sign: Q4 Compensation Adjustment.pdf\nDate: Mon, 19 Oct 2026 16:00:00 +0000\nMessage-ID: <a81@docusign-secure-review.net>\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n<p>Your HR department sent you a document to review and sign.</p><p><a href=\"https://review-docs-7731.pages.dev/sign#YWxleC5tb3JnYW5AZXhhbXBsZS5vcmc=\">REVIEW DOCUMENT</a></p><p>Please complete within 24 hours or the request will expire.</p>\n",
  "lesson": "The sign-here link goes to a site that only looks like DocuSign. Real e-sign emails come from the company's own domain."
 },
 {
  "id": "job-task-telegram",
  "scam": true,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Thu, 12 Nov 2026 09:30:00 +0000\nReceived: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Thu, 12 Nov 2026 09:30:00 +0000\nAuthentication-Results: mx.google.com;\n       dkim=pass header.i=@gmail.com;\n       spf=pass smtp.mailfrom=gmail.com;\n       dmarc=pass (p=NONE) header.from=gmail.com\nFrom: \"Emma | Talent Acquisition\" <emma.talent.recruit26@gmail.com>\nTo: alex.morgan@example.org\nSubject: Remote part-time job opportunity ($300/day)\nDate: Thu, 12 Nov 2026 09:30:00 +0000\nMessage-ID: <CAJ1@mail.gmail.com>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nHello,\n\nWe reviewed your profile and you are selected for a remote part-time position with our marketing agency. The job is simple: you rate products on our platform, 30 tasks a day, and earn up to $300 per day in commission. No interview needed, you can start today.\n\nTo begin, contact our HR manager on Telegram: https://t.me/hr_onboarding_desk\n\nBest regards,\nEmma\n",
  "lesson": "Paid \"tasks\", no interview and a move to Telegram are the marks of a fake job. Real employers never work this way."
 },
 {
  "id": "calendar-payroll-invite",
  "scam": true,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Thu, 12 Nov 2026 09:30:00 +0000\nReceived: from mail.hr-benefits.top (mail.hr-benefits.top [192.0.2.73])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Thu, 12 Nov 2026 09:30:00 +0000\nAuthentication-Results: mx.google.com;\n       dkim=none;\n       spf=softfail smtp.mailfrom=hr-benefits.top;\n       dmarc=none header.from=hr-benefits.top\nFrom: \"HR Payroll\" <payroll@hr-benefits.top>\nTo: alex.morgan@example.org\nSubject: Invitation: Mandatory payroll update @ Fri 13 Nov 2026 10am\nDate: Thu, 12 Nov 2026 09:30:00 +0000\nMessage-ID: <c1@hr-benefits.top>\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=\"B\"\n\n--B\nContent-Type: text/plain; charset=utf-8\n\nYou have been invited to: Mandatory payroll update\n--B\nContent-Type: text/calendar; method=REQUEST; charset=UTF-8\n\nBEGIN:VCALENDAR\nPRODID:-//Microsoft Corporation//Outlook 16.0 MIMEDIR//EN\nVERSION:2.0\nMETHOD:REQUEST\nBEGIN:VEVENT\nORGANIZER;CN=\"Payroll Team\":mailto:payroll@example-hr.top\nATTENDEE;RSVP=TRUE:mailto:alex.morgan@example.org\nDTSTART:20261113T100000Z\nDTEND:20261113T103000Z\nSUMMARY:Mandatory payroll update\nDESCRIPTION:Your salary payment is on hold. Confirm your bank details before\n  the meeting: https://payroll-confirm.top/login\\n\\nHR\nLOCATION:https://payroll-confirm.top/login\nEND:VEVENT\nEND:VCALENDAR\n--B--\n",
  "lesson": "A meeting invite can carry a phishing link too, and your calendar may keep it even after you delete the email."
 },
 {
  "id": "device-code-teams",
  "scam": true,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Mon, 19 Oct 2026 16:00:06 +0000\nReceived: from smtp.meeting-invites.co (smtp.meeting-invites.co [192.0.2.44])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Mon, 19 Oct 2026 16:00:05 +0000\nAuthentication-Results: mx.google.com;\n       dkim=none;\n       spf=pass smtp.mailfrom=meeting-invites.co;\n       dmarc=none header.from=meeting-invites.co\nFrom: \"Microsoft Teams\" <noreply@meeting-invites.co>\nTo: alex.morgan@example.org\nSubject: You have been invited to a secure Teams meeting\nDate: Mon, 19 Oct 2026 16:00:00 +0000\nMessage-ID: <t1@meeting-invites.co>\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n<p>To join the secure meeting, go to <a href=\"https://microsoft.com/devicelogin\">https://microsoft.com/devicelogin</a> and enter the code: KQ7M-T2XRP</p><p>The code expires in 15 minutes.</p>\n",
  "lesson": "Typing a code on a real Microsoft page can still let a stranger in. Only enter codes you asked for yourself."
 },
 {
  "id": "clickfix-captcha",
  "scam": true,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Mon, 19 Oct 2026 16:00:06 +0000\nReceived: from mail.cloud-verify.top (mail.cloud-verify.top [192.0.2.91])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Mon, 19 Oct 2026 16:00:05 +0000\nAuthentication-Results: mx.google.com;\n       dkim=none;\n       spf=neutral smtp.mailfrom=cloud-verify.top;\n       dmarc=none header.from=cloud-verify.top\nFrom: \"Booking Partner Support\" <support@cloud-verify.top>\nTo: alex.morgan@example.org\nSubject: Guest complaint - verify you are human to view\nDate: Mon, 19 Oct 2026 16:00:00 +0000\nMessage-ID: <c1@cloud-verify.top>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nA guest left a complaint. To view it, complete the verification:\n1. Press the Windows key + R\n2. Press Ctrl + V to paste the verification code\n3. Press Enter\nThis opens the Run dialog and confirms you are not a robot.\n",
  "lesson": "No real website asks you to press Windows+R and paste something. That \"CAPTCHA\" installs malware."
 },
 {
  "id": "chase-fraud-alert",
  "scam": false,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Mon, 19 Oct 2026 16:00:06 +0000\nReceived: from mail.chase.com (mail.chase.com [159.53.110.1])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Mon, 19 Oct 2026 16:00:05 +0000\nAuthentication-Results: mx.google.com;\n       dkim=pass header.i=@alertsp.chase.com;\n       spf=pass smtp.mailfrom=alertsp.chase.com;\n       dmarc=pass (p=REJECT) header.from=chase.com\nFrom: Chase <no.reply.alerts@chase.com>\nTo: alex.morgan@example.org\nSubject: Did you make this transaction?\nDate: Mon, 19 Oct 2026 16:00:00 +0000\nMessage-ID: <alert.88@alertsp.chase.com>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nWe noticed a $1,250.00 transaction on your card ending in 4471 at ELECTRONICS STORE.\nIf you don't recognize this transaction, call us at 1-800-935-9935 or reply in the Chase Mobile app. Never share your password or one-time codes with anyone who calls you.\n",
  "lesson": "A real bank alert: it comes from the bank's own domain, passes the checks and doesn't ask for your password."
 },
 {
  "id": "google-docs-share",
  "scam": false,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Mon, 19 Oct 2026 16:00:06 +0000\nReceived: from mail-sor-f73.google.com (mail-sor-f73.google.com [209.85.220.73])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Mon, 19 Oct 2026 16:00:05 +0000\nAuthentication-Results: mx.google.com;\n       dkim=pass header.i=@docs.google.com;\n       spf=pass smtp.mailfrom=3abc@doclist.bounces.google.com;\n       dmarc=pass (p=REJECT) header.from=google.com\nFrom: \"Priya Shah (via Google Docs)\" <drive-shares-dm-noreply@google.com>\nReply-To: Priya Shah <priya.shah@example.org>\nTo: alex.morgan@example.org\nSubject: Document shared with you: \"Q4 planning\"\nDate: Mon, 19 Oct 2026 16:00:00 +0000\nMessage-ID: <000000000000abc@google.com>\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n<p>Priya Shah shared a document with you.</p><p><a href=\"https://docs.google.com/document/d/1AbCdEf/edit?usp=sharing_eil\">Open</a></p><p>Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043, USA. You have received this email because priya.shah@example.org shared a document with you from Google Docs.</p>\n",
  "lesson": "A genuine Google Docs share: sent by Google, and the link goes to docs.google.com."
 },
 {
  "id": "microsoft-security-code",
  "scam": false,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Mon, 19 Oct 2026 16:00:06 +0000\nReceived: from mail-dm6nam11on2100.outbound.protection.outlook.com (mail-dm6nam11on2100.outbound.protection.outlook.com [40.107.223.100])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Mon, 19 Oct 2026 16:00:05 +0000\nAuthentication-Results: mx.google.com;\n       dkim=pass header.i=@accountprotection.microsoft.com;\n       spf=pass smtp.mailfrom=accountprotection.microsoft.com;\n       dmarc=pass (p=REJECT) header.from=accountprotection.microsoft.com\nFrom: Microsoft account team <account-security-noreply@accountprotection.microsoft.com>\nTo: alex.morgan@example.org\nSubject: Microsoft account security code\nDate: Mon, 19 Oct 2026 16:00:00 +0000\nMessage-ID: <MS1@DM6PR11MB.namprd11.prod.outlook.com>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nPlease use the following security code for the Microsoft account al***@example.org.\nSecurity code: 482917\nIf you don't recognize the Microsoft account, you can click https://account.live.com/dp?ft=abc to remove your email address from that account.\nThanks, The Microsoft account team\n",
  "lesson": "A code you asked for, from Microsoft's real domain. If you didn't ask for it, ignore it and never share it."
 },
 {
  "id": "recruiter-interview",
  "scam": false,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Thu, 12 Nov 2026 09:30:00 +0000\nReceived: from mail.northwind.example (mail.northwind.example [198.51.100.20])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Thu, 12 Nov 2026 09:30:00 +0000\nAuthentication-Results: mx.google.com;\n       dkim=pass header.i=@northwind.example;\n       spf=pass smtp.mailfrom=northwind.example;\n       dmarc=pass (p=REJECT) header.from=northwind.example\nFrom: \"Jordan Lee\" <jordan.lee@northwind.example>\nTo: alex.morgan@example.org\nSubject: Interview for the Senior Engineer position\nDate: Thu, 12 Nov 2026 09:30:00 +0000\nMessage-ID: <r1@northwind.example>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nHi Alex,\n\nThanks for your application for the Senior Engineer position. Our hiring team would like to invite you to a first interview next Tuesday, either at our office or on Teams. Please reply with two or three times that work for you, and let me know if you have questions about the role or the salary range.\n\nBest,\nJordan Lee\nTalent Acquisition, Northwind\n",
  "lesson": "A real recruiter: their company's own address, a proper interview, and nothing asked of you but a time."
 },
 {
  "id": "amazon-order-with-phone",
  "scam": false,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Mon, 19 Oct 2026 16:00:06 +0000\nReceived: from a8-30.smtp-out.amazonses.com (a8-30.smtp-out.amazonses.com [54.240.8.30])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Mon, 19 Oct 2026 16:00:05 +0000\nAuthentication-Results: mx.google.com;\n       dkim=pass header.i=@amazon.com header.s=yg4mwqurec7fkhzutopddd3ytuaqrvuz;\n       spf=pass smtp.mailfrom=20261019160000abcd@bounces.amazon.com;\n       dmarc=pass (p=QUARANTINE) header.from=amazon.com\nFrom: \"Amazon.com\" <auto-confirm@amazon.com>\nTo: alex.morgan@example.org\nSubject: Your Amazon.com order #112-4471234-5566778\nDate: Mon, 19 Oct 2026 16:00:00 +0000\nMessage-ID: <0100019a.abc@email.amazonses.com>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nThanks for your order. Order total: $34.99. Arriving Thursday.\nQuestions about your order or a charge you don't recognize? Visit https://www.amazon.com/gp/help or call customer service at 1-888-280-4331.\n",
  "lesson": "A real order email can include a support number. What matters is who sent it and what it asks."
 },
 {
  "id": "personal-reply-gmail",
  "scam": false,
  "raw": "Delivered-To: alex.morgan@example.org\nReceived: by 2002:a05:7300:1234 with SMTP id q1csp1; Mon, 19 Oct 2026 16:00:06 +0000\nReceived: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])\n        by mx.google.com with ESMTPS id x1si2\n        for <alex.morgan@example.org>; Mon, 19 Oct 2026 16:00:05 +0000\nAuthentication-Results: mx.google.com;\n       dkim=pass header.i=@gmail.com header.s=20230601;\n       spf=pass smtp.mailfrom=jamie.lee@gmail.com;\n       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com\nFrom: Jamie Lee <jamie.lee@gmail.com>\nTo: alex.morgan@example.org\nSubject: Re: Saturday hike?\nIn-Reply-To: <CAB1x@mail.gmail.com>\nReferences: <CAB1x@mail.gmail.com>\nDate: Mon, 19 Oct 2026 16:00:00 +0000\nMessage-ID: <CAC2y=uR@mail.gmail.com>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nSounds great! Let's meet at the trailhead at 8. I'll bring snacks.\n",
  "lesson": "A friend replying from Gmail is normal. Gmail only becomes a red flag when someone claims to be a company or your boss."
 }
];

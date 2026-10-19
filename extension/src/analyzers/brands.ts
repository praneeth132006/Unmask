/**
 * Frequently impersonated brands and the domains they legitimately send from
 * or link to. `keywords` are matched against display names and domain labels.
 */
export interface Brand {
  name: string;
  keywords: string[];
  domains: string[];
}

export const BRANDS: Brand[] = [
  { name: 'PayPal', keywords: ['paypal'], domains: ['paypal.com', 'paypal.me', 'paypalobjects.com', 'paypal-communication.com'] },
  { name: 'Apple', keywords: ['apple', 'icloud', 'itunes', 'appleid'], domains: ['apple.com', 'icloud.com', 'me.com', 'itunes.com', 'apple.news'] },
  { name: 'Microsoft', keywords: ['microsoft', 'office365', 'office 365', 'outlook', 'onedrive', 'sharepoint', 'hotmail', 'xbox'], domains: ['microsoft.com', 'office.com', 'office365.com', 'outlook.com', 'live.com', 'hotmail.com', 'onedrive.com', 'sharepoint.com', 'microsoftonline.com', 'xbox.com', 'azure.com', 'microsoft365.com', 'msn.com', 'skype.com'] },
  { name: 'Google', keywords: ['google', 'gmail', 'youtube'], domains: ['google.com', 'gmail.com', 'youtube.com', 'googlemail.com', 'withgoogle.com', 'goo.gl', 'g.co', 'googleusercontent.com', 'googleapis.com', 'gstatic.com', 'google-analytics.com', 'doubleclick.net', 'googletagmanager.com'] },
  { name: 'Amazon', keywords: ['amazon', 'aws', 'prime video'], domains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazonses.com', 'aws.amazon.com', 'amazonaws.com', 'primevideo.com', 'a.co'] },
  { name: 'Netflix', keywords: ['netflix'], domains: ['netflix.com', 'nflxext.com', 'nflximg.net'] },
  { name: 'Meta / Facebook', keywords: ['facebook', 'meta', 'messenger'], domains: ['facebook.com', 'facebookmail.com', 'fb.com', 'meta.com', 'messenger.com'] },
  { name: 'Instagram', keywords: ['instagram'], domains: ['instagram.com', 'mail.instagram.com'] },
  { name: 'WhatsApp', keywords: ['whatsapp'], domains: ['whatsapp.com', 'whatsapp.net'] },
  { name: 'LinkedIn', keywords: ['linkedin'], domains: ['linkedin.com', 'lnkd.in', 'licdn.com'] },
  { name: 'X / Twitter', keywords: ['twitter'], domains: ['twitter.com', 'x.com', 't.co'] },
  { name: 'GitHub', keywords: ['github'], domains: ['github.com', 'githubusercontent.com', 'github.io'] },
  { name: 'DHL', keywords: ['dhl'], domains: ['dhl.com', 'dhl.de', 'dhl.co.uk', 'dhl.in'] },
  { name: 'FedEx', keywords: ['fedex'], domains: ['fedex.com'] },
  { name: 'UPS', keywords: ['ups'], domains: ['ups.com'] },
  { name: 'USPS', keywords: ['usps'], domains: ['usps.com', 'usps.gov'] },
  { name: 'Chase', keywords: ['chase', 'jpmorgan'], domains: ['chase.com', 'jpmorgan.com', 'jpmorganchase.com'] },
  { name: 'Bank of America', keywords: ['bankofamerica', 'bank of america'], domains: ['bankofamerica.com', 'bofa.com', 'ealerts.bankofamerica.com'] },
  { name: 'Wells Fargo', keywords: ['wellsfargo', 'wells fargo'], domains: ['wellsfargo.com'] },
  { name: 'Citi', keywords: ['citibank'], domains: ['citi.com', 'citibank.com'] },
  { name: 'HSBC', keywords: ['hsbc'], domains: ['hsbc.com', 'hsbc.co.uk', 'hsbc.co.in'] },
  { name: 'Coinbase', keywords: ['coinbase'], domains: ['coinbase.com'] },
  { name: 'Binance', keywords: ['binance'], domains: ['binance.com'] },
  { name: 'MetaMask', keywords: ['metamask'], domains: ['metamask.io', 'consensys.io'] },
  { name: 'DocuSign', keywords: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
  { name: 'Dropbox', keywords: ['dropbox'], domains: ['dropbox.com', 'dropboxmail.com'] },
  { name: 'Adobe', keywords: ['adobe'], domains: ['adobe.com', 'adobesign.com', 'adobe.io'] },
  { name: 'Steam', keywords: ['steam', 'steampowered'], domains: ['steampowered.com', 'steamcommunity.com'] },
  { name: 'Spotify', keywords: ['spotify'], domains: ['spotify.com'] },
  { name: 'eBay', keywords: ['ebay'], domains: ['ebay.com', 'ebay.in', 'ebay.co.uk'] },
  { name: 'Walmart', keywords: ['walmart'], domains: ['walmart.com'] },
  { name: 'IRS', keywords: ['irs'], domains: ['irs.gov'] },
  { name: 'Zoom', keywords: ['zoom'], domains: ['zoom.us', 'zoom.com'] },
  { name: 'Slack', keywords: ['slack'], domains: ['slack.com'] },
  { name: 'Okta', keywords: ['okta'], domains: ['okta.com', 'oktapreview.com'] },
  { name: 'Norton', keywords: ['norton'], domains: ['norton.com', 'nortonlifelock.com', 'gen.digital'] },
  { name: 'McAfee', keywords: ['mcafee'], domains: ['mcafee.com'] },
  { name: 'Venmo', keywords: ['venmo'], domains: ['venmo.com'] },
  { name: 'Cash App', keywords: ['cashapp', 'cash app'], domains: ['cash.app', 'square.com', 'squareup.com'] },
  { name: 'Revolut', keywords: ['revolut'], domains: ['revolut.com'] },
  { name: 'Wise', keywords: ['transferwise'], domains: ['wise.com', 'transferwise.com'] },
  { name: 'SBI', keywords: ['sbi', 'state bank of india', 'onlinesbi'], domains: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'sbi.bank.in'] },
  { name: 'HDFC Bank', keywords: ['hdfc', 'hdfcbank'], domains: ['hdfcbank.com', 'hdfc.com', 'hdfcbank.net', 'hdfc.bank.in'] },
  { name: 'ICICI Bank', keywords: ['icici', 'icicibank'], domains: ['icicibank.com', 'icici.bank.in'] },
  { name: 'Axis Bank', keywords: ['axisbank', 'axis bank'], domains: ['axisbank.com', 'axis.bank.in'] },
  { name: 'Paytm', keywords: ['paytm'], domains: ['paytm.com', 'paytm.in'] },
  { name: 'PhonePe', keywords: ['phonepe'], domains: ['phonepe.com'] },
  { name: 'Flipkart', keywords: ['flipkart'], domains: ['flipkart.com'] },
  { name: 'Airtel', keywords: ['airtel'], domains: ['airtel.in', 'airtel.com'] },
  { name: 'Jio', keywords: ['jio', 'reliance jio'], domains: ['jio.com', 'ril.com'] },
  { name: 'Income Tax India', keywords: ['incometax', 'income tax department'], domains: ['incometax.gov.in', 'incometaxindia.gov.in'] },
];

export function isBrandDomain(brand: Brand, registrable: string): boolean {
  return brand.domains.some((d) => registrable === d || registrable.endsWith(`.${d}`));
}

/** The brand whose legitimate domains include this registrable domain, if any. */
export function brandOwningDomain(registrable: string): Brand | null {
  return BRANDS.find((b) => b.domains.includes(registrable)) ?? null;
}

/** Brands whose name appears as a whole word in free text such as a display name. */
export function brandsMentionedIn(text: string): Brand[] {
  const hay = ` ${text.toLowerCase().replace(/[^a-z0-9]+/g, ' ')} `;
  const compact = text.toLowerCase().replace(/[^a-z0-9]/g, '');
  return BRANDS.filter((b) =>
    b.keywords.some((k) => {
      const words = k.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
      if (hay.includes(` ${words} `)) return true;
      // "PayPalService" style run-ons, only for distinctive keywords.
      return words.length >= 6 && !words.includes(' ') && compact.includes(words);
    }),
  );
}

export const FREE_MAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.in', 'yahoo.co.uk', 'ymail.com', 'outlook.com', 'hotmail.com',
  'live.com', 'msn.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com', 'protonmail.com', 'proton.me', 'pm.me',
  'gmx.com', 'gmx.net', 'gmx.de', 'mail.com', 'zoho.com', 'zohomail.com', 'yandex.com', 'yandex.ru', 'mail.ru',
  'tutanota.com', 'tuta.io', 'rediffmail.com', 'qq.com', '163.com', 'web.de', 'inbox.com', 'fastmail.com',
]);

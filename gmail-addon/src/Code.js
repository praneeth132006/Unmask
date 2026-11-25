/**
 * Unmask for Gmail (Google Workspace add-on). Works in Gmail on the web and in
 * the Gmail apps for Android and iPhone. The open message is read with the
 * add-on's read-only permission and checked here, inside your own Google
 * account's Apps Script runtime; it is never sent to an Unmask server.
 */
var COLORS = { high: '#d93025', suspicious: '#e37400', clear: '#188038' };

function onHomepage() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Unmask').setSubtitle('Open an email to check it'))
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(
      'Open any email and Unmask shows, in plain words, whether it looks like a scam: who really sent it, where its links go and what it asks you to do.')))
    .build();
}

async function onGmailMessageOpen(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message = GmailApp.getMessageById(e.gmail.messageId);
  var raw = message.getRawContent();
  if (raw.length > 4 * 1024 * 1024) raw = raw.slice(0, 4 * 1024 * 1024);
  // The engine never waits on timers or the network, so the V8 runtime settles it within this call.
  var result = await Unmask.check(raw);
  return buildCard_(result, message.getSubject());
}

function buildCard_(r, subject) {
  var header = CardService.newCardHeader()
    .setTitle(r.label + ' · ' + r.score + '/100')
    .setSubtitle(subject || '(no subject)');
  var summary = CardService.newCardSection()
    .addWidget(CardService.newDecoratedText().setTopLabel('In plain words').setText('<b><font color="' + COLORS[r.verdict] + '">' + escape_(r.headline) + '</font></b>').setWrapText(true));
  r.reasons.forEach(function (reason) { summary.addWidget(CardService.newTextParagraph().setText('• ' + escape_(reason))); });
  summary.addWidget(CardService.newDecoratedText().setTopLabel('What to do').setText(escape_(r.action)).setWrapText(true));

  var card = CardService.newCardBuilder().setHeader(header).addSection(summary);
  if (r.flags.length) {
    var flags = CardService.newCardSection().setHeader('Red flags').setCollapsible(r.flags.length > 3).setNumUncollapsibleWidgets(3);
    r.flags.forEach(function (f) {
      var w = CardService.newDecoratedText().setText(escape_(f.title)).setBottomLabel(escape_(f.detail).slice(0, 180)).setWrapText(true);
      if (f.lesson) w.setButton(CardService.newTextButton().setText('How it works').setOpenLink(CardService.newOpenLink().setUrl(f.lesson)));
      flags.addWidget(w);
    });
    card.addSection(flags);
  }
  card.addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(
    '<font color="#5f6368">Checked in your own Google account. Nothing was sent to Unmask. Unmask never says an email is “safe”.</font>')));
  return card.build();
}

function escape_(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

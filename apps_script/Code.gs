// GooseRelay forwarder.
//
// Apps Script web app deployed as: Execute as: Me, Access: Anyone (or Anyone with Google account).
// All traffic is AES-GCM encrypted by the client; this script is a dumb pipe
// and never sees plaintext or holds the key.
//
// Wire: client POSTs base64(encrypted batch). We forward the bytes verbatim
// to RELAY_URL and return its response body verbatim.
//
// Replace RELAY_URL with your VPS address before deploying.

const RELAY_URL = 'http://YOUR.VPS.IP:8443/tunnel';
const FORWARDER_VERSION = 1;
const PROTOCOL_VERSION = 2;

function doPost(e) {
  const payload = (e && e.postData && e.postData.contents) || '';
  const resp = UrlFetchApp.fetch(RELAY_URL, {
    method: 'post',
    contentType: 'text/plain',
    payload: payload,
    muteHttpExceptions: true,
    followRedirects: false,
    deadline: 30,  // seconds; long-poll window is kept at 8s for Apps Script stability
  });
  return ContentService
    .createTextOutput(resp.getContentText())
    .setMimeType(ContentService.MimeType.TEXT);
}

// doGet returns lightweight forwarder metadata for pre-flight checks. It must
// stay off the doPost hot path: PropertiesService writes on every tunnel POST
// add latency and contention during page-load request bursts.
function doGet(e) {
  if (e && e.parameter && e.parameter.legacy === '1') {
    return ContentService
      .createTextOutput('GooseRelay forwarder OK')
      .setMimeType(ContentService.MimeType.TEXT);
  }
  const out = {
    ok: true,
    version: FORWARDER_VERSION,
    protocol: PROTOCOL_VERSION,
  };
  return ContentService
    .createTextOutput(JSON.stringify(out))
    .setMimeType(ContentService.MimeType.JSON);
}

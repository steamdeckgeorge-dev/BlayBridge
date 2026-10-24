// Cloudflare Pages Function: region hint only, no personal data stored.
// EU/EEA, UK and Switzerland use Google's certified AdSense CMP instead of a second banner.
const cmpCountries = new Set('AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE IS LI NO GB CH'.split(' '));
export function onRequest(context) {
  const country = String(context.request.cf?.country || '').toUpperCase();
  return new Response(JSON.stringify({googleCmpRegion: cmpCountries.has(country),known: !!country}), {
    headers: {'content-type':'application/json; charset=utf-8','cache-control':'private, no-store','x-content-type-options':'nosniff'}
  });
}

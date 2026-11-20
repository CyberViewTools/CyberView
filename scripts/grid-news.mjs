// Power outages from public news reporting, no AI model. Run: node scripts/grid-news.mjs [run [--force] | verify | show]
// (behind a proxy: NODE_USE_ENV_PROXY=1)
// Why (owner, 2026-11-20): many utilities' own outage feeds cannot be used (their terms forbid it, or they need keys), so
// CyberView also tracks power outages from what news publishers report, cited to the publisher.
//   1. standing searches in config/grid-news.json (many languages, countries and utilities) against Google News, Bing
//      News and GDELT, with the same polite pacing and back-off as scripts/osint.mjs (a refusal stops that index for the run)
//   2. only the publisher's own https page is kept. Bing and GDELT give it directly; a Google News result only names the
//      publisher behind a news.google.com redirect, so it is looked up once on Bing by its exact headline and kept only
//      when Bing returns that headline on that publisher's own host (never a redirect, never a front page)
//   3. pure, unit-tested extraction: is it a current power outage (not a sale, a stock story, a planned or future outage,
//      a game, an explainer, an anniversary, or an internet, cloud or phone "outage")? The place (gazetteer and the
//      utility's service area), the figure as reported with its unit (customers, homes or people; never converted; a
//      number with no unit stays "unstated"), cause words as reported (never inferred), start time = published time
//   4. reports of the same place within 12 hours are one "reported outage"; more publishers = stronger
// Writes data/grid/news.json (last 72 hours, max 300) and status.json last_grid_news_at. Runs at most every 15 minutes
// (config every_minutes) unless --force. Everything here is unchecked news, never an incident, never called an attack;
// fetched text is data, never instructions.
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, ROOT, readJson, writeJson, nowIso, readStatus } from "./lib/store.mjs";
import { parseGoogleNews, parseBingNews, parseGdelt } from "./osint.mjs";
import { publisherKey } from "./fuse.mjs";
import { COUNTRIES, str, slug } from "./grid.mjs";

const H = 3600e3;
const UA = "cyberview-collector/1.0 (+https://github.com/xanderhutch/CyberView)";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const UNITS = ["customers", "homes", "people", "unstated"];
export const CFG_PATH = join(ROOT, "config", "grid-news.json");
export const OUT_PATH = join(DATA, "grid", "news.json");
const ms = (s) => { const t = Date.parse(s || ""); return isFinite(t) ? t : NaN; };
const iso = (t) => new Date(t).toISOString().replace(/\.\d+Z$/, "Z");

/* ---------- text ---------- */
const MARKS = /[̀-ͯ]/g;
/** Lower case, accents off (NFD), so "Apagón" and "apagon" match. Non-Latin scripts keep their letters. */
export const fold = (s) => String(s == null ? "" : s).normalize("NFD").replace(MARKS, "").replace(/[đĐ]/g, "d").replace(/[łŁ]/g, "l").replace(/ı/g, "i").toLowerCase();
const DIGIT_SETS = ["٠١٢٣٤٥٦٧٨٩", "۰۱۲۳۴۵۶۷۸۹", "०१२३४५६७८९", "০১২৩৪৫৬৭৮৯", "０１２３４５６７８９"];
/** Arabic-Indic, Persian, Devanagari, Bengali and full-width digits as ASCII. */
export function asciiDigits(s) {
  let out = String(s == null ? "" : s);
  for (const set of DIGIT_SETS) for (let d = 0; d < 10; d++) out = out.split(set[d]).join(String(d));
  return out.replace(/٬/g, ",").replace(/٫/g, ".");
}
const prep = (s) => fold(asciiDigits(s)).replace(/[’`´]/g, "'").replace(/\s+/g, " ").trim();
// a regex written with accents is compared with folded text: fold its source the same way (never lower-case a source)
// \w is ASCII only, even with the u flag: in these patterns it means a letter of any script
const rx = (src, flags = "iu") => new RegExp(String(src).replace(/\\w/g, "[\\p{L}\\p{N}_]").normalize("NFD").replace(MARKS, "").replace(/đ/g, "d").replace(/ł/g, "l").replace(/ı/g, "i"), flags);
const B = "(?<![\\p{L}\\p{N}])", E = "(?![\\p{L}\\p{N}])";
// Chinese, Japanese, Korean and Thai write words without spaces: those alternatives match anywhere, the others as words
const NOSPACE = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Thai}]/u;
export function splitAlternatives(src) {
  const out = []; let depth = 0, cls = false, cur = "";
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === "\\") { cur += c + (src[i + 1] || ""); i++; continue; }
    if (cls) { if (c === "]") cls = false; cur += c; continue; }
    if (c === "[") cls = true; else if (c === "(") depth++; else if (c === ")") depth--;
    if (c === "|" && depth === 0) { out.push(cur); cur = ""; } else cur += c;
  }
  out.push(cur);
  return out;
}
const w = (src) => {
  const alts = splitAlternatives(src), sp = alts.filter((a) => !NOSPACE.test(a)), ns = alts.filter((a) => NOSPACE.test(a));
  return rx([sp.length ? `${B}(?:${sp.join("|")})${E}` : "", ns.length ? `(?:${ns.join("|")})` : ""].filter(Boolean).join("|"));
};

/* ---------- is it a current power outage? ---------- */
// specific phrases, per language; "outage" alone is not enough (internet, cloud and phone outages use it too)
export const POWER = [
  w("power (outage|cut|failure|loss|interruption|disruption)s?|(without|no|lost|lose|loses|losing|restor\\w*|knock\\w* out|cut) (the )?(power|electricity)|power (is |was )?(out|back|restored)|power (\\w+ )?restored|blackouts?|brown-?outs?|load[- ]?shedding|(grid|electric(al)?|electricity|power) (collapse[sd]?|collapsing|failure|outages?|disruptions?|disturbance|blackout)|electricity (cuts?|supply (cut|disrupted|interrupted))|in the dark|outage map"),
  w("pannes? (de courant|d'electricite|electriques?|de secteur)|coupures? (de courant|d'electricite|electriques?)|prives? (d'electricite|de courant)|sans (electricite|courant)|delestages?|black-?out"),
  w("apagon(es)?|cortes? (de|del) (luz|energia|suministro|servicio electrico|electricidad)|sin (luz|electricidad|energia electrica|servicio electrico)|falla(s)? electrica|interrupcion del (suministro|servicio) electrico|colapso del sistema electrico"),
  w("apagao|apagoes|falta de (energia|luz)|sem (luz|energia)|queda de energia|interrupc(ao|oes) (de|no fornecimento de) energia|corte de energia"),
  w("stromausfall|stromausfalle|stromabschaltung|ohne strom|stromunterbrechung|strom ausgefallen|stromstorung"),
  w("(senza|niente) (corrente|luce|elettricita)|interruzion[ei] (di corrente|elettric[ah]e?|dell'energia)|guasto elettrico|black ?out elettrico"),
  w("stroomstoring(en)?|stroomuitval|zonder stroom"),
  w("awari[ai] (pradu|sieci energetycznej|energetyczn\\w*)|bez pradu|brak pradu|przerw[ay] w dostawie (pradu|energii)"),
  rx("(відключенн\\w* (світла|електро\\w*)|знеструмлен\\w*|без світла|без електро\\w*|блекаут\\w*|аварійн\\w* відключенн\\w*|графік\\w* відключен\\w*)"),
  rx("(отключени\\w* (света|электр\\w*)|без света|без электричества|обесточ\\w*|блэкаут\\w*|блекаут\\w*)"),
  w("elektrik kesinti\\w*|elektriksiz|elektrikler kesildi|karanliga gomuldu"),
  rx("(انقطاع (التيار )?الكهرباء|انقطاع التيار الكهربائي|انقطاع الكهرباء|بدون كهرباء|تخفيف الأحمال|إظلام)"),
  rx("(बिजली (कटौती|गुल|संकट|आपूर्ति ठप|बंद)|ब्लैकआउट|लोड शेडिंग)"),
  rx("(بجلی (بند|غائب|کی بندش|معطل)|لوڈشیڈنگ|لوڈ شیڈنگ|بریک ڈاؤن)"),
  rx("(লোডশেডিং|বিদ্যুৎ (বিভ্রাট|বিচ্ছিন্ন|নেই|সংকট)|ব্ল্যাকআউট)"),
  w("pemadaman (listrik|bergilir)|listrik padam|mati listrik|padam listrik|gangguan (listrik|bekalan elektrik)|bekalan elektrik terputus|terputus bekalan elektrik"),
  rx("(停電|停电|斷電|断电|大規模停電|大停电)"),
  rx("정전(?!\\s?(협정|체제|선언|기|협상|\\d+\\s?주년))"),
  w("mat dien|cup dien|cat dien|su co luoi dien"),
  w("kukatika (kwa )?umeme|kukosa umeme|mgao wa umeme|hitilafu ya umeme"),
  rx("(διακοπ\\w* (ρευματος|ρεύματος|ηλεκτροδοτησ\\w*)|μπλακ ?αουτ|χωρις ρευμα|χωρίς ρεύμα)"),
  w("pana de curent|fara curent|fara energie electrica|vypadek (proudu|elektriny)|bez proudu|aramszunet|aramkimaradas|stromavbrott|utan strom|strombrudd|uten strom|strømbrudd|stromafbrydelse|stromsvigt|strømafbrydelse|sahkokatko\\w*|sahkot poikki|nestanak struje|bez struje|nestalo struje"),
  rx("(הפסק\\w* חשמל|ללא חשמל|ไฟดับ|ไฟฟ้าดับ|قطعی برق|خاموشی)"),
  w("brownout|walang kuryente"),
];
const OUTAGE_WORD = w("outages?|power|electricity|electric");
const OUTAGE_ONLY = w("outages?|interruptions?");
// guards: [reason code, pattern]; the first that fires rejects the report (codes are counted in news.json stats)
export const GUARDS = [
  ["ad", w("sponsored|advertorial|paid (content|post)|partner content|anzeige|publireportage|publirreportaje")],
  ["not_grid", w("(internet|online|network|cell(ular)?|phone|mobile|wireless|broadband|fiber|fibre|cable tv|911|e911|cloud|aws|azure|microsoft( 365)?|google|apple|icloud|outlook|teams|server|website|app|platform|software|tech|technology|it|payment|banking|bank|airline|flight|crowdstrike|cloudflare|starlink|verizon|at&t|t-mobile|comcast|xfinity|spectrum|optus|telstra|vodafone|data cent(er|re)|chatgpt|openai|whatsapp|instagram|facebook|x|youtube|discord|steam|playstation|xbox) (outage|blackout|disruption)s?|(internet|media|news|communications?|information|radio|tv|television|broadcast|social media|phone|telecom|data|digital) blackouts?|blackouts? (of|on) (the )?(internet|news|media)|internet shutdowns?|apagon (analogico|digital|informativo|tecnologico|de internet|de redes|de whatsapp|de telefonia)|panne (informatique|internet|de reseau|du reseau mobile)|black ?out (informatico|informativo|mediatico)")],
  ["not_grid", w("blackout (dates?|period|window|curtains?|rules?|restrictions?|poetry|drunk|challenge|tuesday|bingo|mode|map|game|sale|friday|tattoo)|black ops|warzone|call of duty|(tv|nfl|mlb|nba|nhl|espn|fox|streaming|broadcast|local) blackout|blacked out|blackout (in|on) (espn|fox|tv)")],
  ["entertainment", w("video ?games?|gaming|esports?|fortnite|minecraft|roblox|nintendo|movie|film|trailer|netflix|album|song|novel|anime|manga|box office|tv series|tv episode|reality show|horror|thriller|pelicula|serie de tv|cancion|filme|film d'|spielfilm")],
  ["market", w("compensation|compensacion|indemniz\\w*|pagara|lawsuit|class action|fined|multad[oa]|multa de|stocks?|shares?|share price|investors?|earnings|dividends?|stake|acquisitions?|acquires?|merger|ipo|price target|analysts?|buyback|revenue|profits?|quarterly results|q[1-4] results|bonds?|nasdaq|nyse|tsx|asx|valuation|market cap|rate case|rate (hike|increase)s?|electric bills?|tariffs?|bolsa|acciones|cotizacion|aktien?|borse|bourse|acoes|dividendos?|investidores|inversores|beneficios|lucros?|utili trimestrali")],
  ["product", w("jackery|ecoflow|anker|bluetti|power ?banks?|notstrom\\w*|akku\\w*|蓄電池|deals?|discount|on sale|for sale|sale price|black friday|cyber monday|best (\\w+ )?(generators?|power stations?|power banks?|batteries|flashlights|lanterns|ups)|buy(ing)? (a |the )?(generator|power station|power bank|battery)|\\$\\d+ off|amazon|walmart|costco|home depot|lowe's|product review")],
  ["planned", w("saatler|sokaklar|hangi (ilce|mahalle)\\w*|δειτε που|σε ποιες περιοχες|προγραμματισμεν\\w*|confirma\\w* (el |la )?(corte|interrupcion|suspension)\\w*|hoy,? (lunes|martes|miercoles|jueves|viernes|sabado|domingo) \\d|programi|listesi|aciklandi|olmayacak|jadwal|planowan\\w*|(corte|cortes) de (luz|energia) (el|este|para el|del) (\\d|lunes|martes|miercoles|jueves|viernes|sabado|domingo)|zonas afectadas|revisa (las|los)|confirma corte|anuncia\\w* corte\\w*|drills?|exercises?|simulat\\w*|probt|ubung|testlauf|simulacro|exercice|horarios (de|confirmados)|calendario de cortes|cronograma de cortes|(outage|cut|interruption|shutdown)s? (is |are )?(planned|scheduled)|planned (power |electricity )?(outage|interruption|maintenance|shutdown|cut|work)s?|scheduled (power |electricity )?(outage|interruption|maintenance|shutdown|cut|work)s?|maintenance (outage|work)s?|(power|electricity) (shutdown|cut|outage) (for|due to) (maintenance|upgrades?|works?|repairs)|(cortes?|apagon(es)?|interrupcion(es)?|suspension(es)?) (de luz |de energia |del servicio )?programad[oa]s?|mantenimiento programado|cortes? (de luz )?por mantenimiento|coupures? (de courant |d'electricite )?programmees?|travaux programmes|geplante (stromabschaltung|abschaltung|unterbrechung|stromunterbrechung|wartung)|planmassige|interruzion[ei] programmat[ae]|lavori programmati|geplande (onderbreking|stroomonderbreking|werkzaamheden)|planowane (wylaczenie|wylaczenia|przerwy)|planow\\w+ wylacz\\w*|планов\\w* (отключ\\w*|відключ\\w*)|planli (elektrik )?kesinti\\w*|programli kesinti\\w*|계획정전|pemeliharaan|lich (cat|cup) [đd]ien|พรุ่งนี้|ประกาศ|งดจ่ายกระแสไฟฟ้า|เช็ก(เลย)?(ที่ไหน|พิกัด)|เช็คพิกัด|αυριο|διακοπες ρευματος (σε περιοχες|αυριο)|δεδδηε|hedno|جداول|مخطط\\w*|announce[sd]?|to face|will face")],
  ["explainer", w("сонячн\\w* панел\\w*|скільки (коштує|доведеться)|solar panels?|rumou?r\\w*|hipotesis|supervivencia|survival kit|kit de|miedo|temor|(apagon|apagao|blackout|panne|stromausfall) (mundial|global|mondial\\w*|weltweit\\w*)|(world|global|worldwide|nationwide 90-day) blackout|teorias?|bulos?|boatos?|conspira\\w*|falso|страшилк\\w*|фейк\\w*|чутк\\w*|слух\\w*|scientists|researchers|new study|study (finds|shows)|вчені|учені|ученые|cientificos|investigadores|forscher|chercheurs|pesquisadores|beachten|ratgeber|vorsorge|notfallvorrat|備え|対策|防災|備蓄|とは|方法|べきか|どう|how to|what to do|tips|guide|explained|explainer|debunk\\w*|fact[- ]?check\\w*|rumou?rs?|hoax|conspiracy|myths?|viral (claim|post|video)|fake|90-day blackout|what (you|we) (need to )?know|things to know|q&a|faq|podcast|webinar|op-?ed|opinion|editorial|column|survival|checklist|stay (safe|warm|cool)|food safety|keep (your )?food|refrigerator|carbon monoxide (safety|tips|warning)|prepar(e|ing|edness) (for|kit)|stock(ing)? up|como (actuar|prepararse)|que hacer|consejos|que faire|conseils|was tun|tipps|cosa fare|consigli|wat te doen|co robic|что делать|як (діяти|підготуватися)|ne yapmali|ماذا تفعل|क्या करें|cara (menghadapi|mengatasi)|photos? of the day|gallery|in pictures|як (у|в) \\w+ (забезпечують|працюють)|під час (блекаут|відключен)\\w*|during (blackouts|outages)")],
  ["past", w("desde o apagao|desde el apagon|since the (big |great |national )?blackout|(\\d+|dos|tres|cuatro) anos|meses despues|years later|anniversary|\\d+ years? (ago|after|since|on)|years? (ago|after|later)|a year (ago|after|on|since)|one year (ago|after|on|since)|retrospective|documentary|history of|lessons (from|of|learned)|report (into|on) (the|last)|inquiry (into|finds)|investigation (finds|report)|final report|(19|20)\\d\\d (blackout|outage|apagon|stromausfall|panne)|aniversario|hace (un|\\d+) anos?|anniversaire|il y a (un|\\d+) ans|jahrestag|vor (einem|\\d+) jahren|anniversario|anni fa|rocznic\\w*|lat temu|годовщин\\w*|лет назад|років тому|yil once|yildonumu|ذكرى|साल पहले|周年|年前|주년|nam truoc")],
  ["none_now", w("(no|zero) (load ?shedding|outages?)|(suspend\\w*|ends?|ended|lifted|halts?|halted|scraps?) load ?shedding|(\\d+|consecutive) days? (without|of no) (load ?shedding|outages?)|load ?shedding[- ]free|sin apagones|sem apagao|без відключень|без отключений|reduc\\w* (load ?shedding|outages|power cuts)|reduit les coupures|fewer outages")],
  ["not_current", w("\\d+ ?% (of )?outages|repair delays|for (weeks|months)|laments|slams|celebrity|actor|singer|rapper|співак|актор")],
];
export const FUTURE_STRONG = w("posibles?|possible|possivel|alerta por|може|можлив\\w*|возможн\\w*|habra|habria|havera|haveria|aconteceria|podria|could (leave|lose|see|face|knock|cause|bring|hit)|may (leave|lose|see|face|knock|cause|bring)|might (leave|lose|see|face|cause)|at risk|risk of|warns? (of|about)|warning of|prepar(e|es|ed|ing) for|bracing|brace for|ahead of|forecast|expected to|likely to|set to|threat(en)?s? (to|of)|in case of|what if|podria(n)? (dejar|provocar|causar)|riesgo de|pourrai(t|ent) (provoquer|priver|entrainer)|risque de|konnte|drohen?|potrebbe|rischio (di )?|zou kunnen|moze (dojsc|spowodowac)|grozi|может (привести|оставить)|могут|можуть|загроза|угроза|olabilir|riski|恐れ|おそれ|우려|co the");
export const FUTURE = w("dejara|quedara|quedaran|tendra|την (δευτερα|τριτη|τεταρτη|πεμπτη|παρασκευη|κυριακη)|το σαββατο|will|would|can|fears?|concerns?|worr(y|ies)|este (lunes|martes|miercoles|jueves|viernes|sabado|domingo)|esta (semana|noche)|sera|seria|va a|vai|anuncia\\w*|tomorrow|tonight|upcoming|next (week|month|year|summer|winter|weekend)|this weekend|on (monday|tuesday|wednesday|thursday|friday|saturday|sunday)|by 20\\d\\d|drill|exercise|simulation|scenario|plans? (to|for)|planning|proposed|project|manana|demain|morgen|domani|jutro|завтра|yarin|غدا|कल|besok|明日|내일|ngay mai|kesho");
export const PRESENT = w("the power (is |was )?out|power is out|without (power|electricity)|lost power|los(e|es|ing) power|left (\\w+ ){0,5}(without|in the dark)|knock(ed|s) out|remains? without|still without|restored|restoring|hit by|plunge[sd]? (\\w+ ){0,3}into darkness|are without|is without|were without|in the dark|outages? (hit|hits|leave|leaves|left|affect|affects|affected)|sin luz|sin energia|sans (electricite|courant)|prives? d'electricite|ohne strom|senza (luce|corrente)|zonder stroom|bez pradu|без света|без світла|без электричества|знеструмлен\\w*|обесточ\\w*|elektriksiz|بدون كهرباء|गुल|padam|mat dien|bila umeme|restablec\\w*|restabelec\\w*|retabli\\w*|wiederhergestellt|ripristinat\\w*|hersteld|przywrocon\\w*|восстановл\\w*|відновл\\w*");
// a present phrase after a future auxiliary is still the future ("Cali tendrá un apagón ... se quedará sin energía")
export const PRESENT_AFTER_FUTURE = w("(quedara|quedaran|estara|estaran|tendra|tendran|ficara|ficarao|will( be| leave| have| remain)?|seront|wird|werden) (\\w+ ){0,3}(sin|without|sem|sans|ohne|senza|zonder|bez)");
// what has already happened, for headlines that also speak of what could come next
export const PAST = w("lost power|knock(ed|s) out|left (\\w+ ){0,5}(without|in the dark)|are without|is without|were without|remains? without|still without|restored|restoring|hit by|залишил\\w*|остал\\w*|se quedaron|quedaron sin|ficaram sem|sont prives|waren ohne");
const QUESTION = /[?¿]|(^|\s)чи\s|^(how|why|what|when|where|who|is|are|can|should|do|does|will|which)\s|^(como|por que|que|cuando|donde|quien|wie|warum|was|pourquoi|comment|perche|come|чи|как|почему|що|як)\s/i;
export const CYBER = w("cyber[- ]?attacks?|cyber[- ]?incident|cyberattaques?|ciberataques?|ataque (hacker|cibernetico|informatico)|cyberangriffs?|hackerangriffs?|attacco informatico|attacchi informatici|cyberatak\\w*|atak hakerski\\w*|кибератак\\w*|кібератак\\w*|хакер\\w*|siber saldiri\\w*|هجوم سيبراني|هجمات سيبرانية|साइबर हमला|serangan siber|サイバー攻撃|사이버 ?공격|网络攻击|網路攻擊|tan cong mang|hack(ed|ers?|ing)?|ransomware|malware");
export const ATTACK_WORDS = ["cyberattack", "attack", "sabotage", "strike", "missile", "drone", "shelling", "theft", "vandalism"];

// month names (folded) -> month index, for dates written in headlines
const MONTHS = {};
[["january jan enero janeiro janvier januar gennaio ocak ιανουαριου ม.ค.", 0], ["february feb febrero fevereiro fevrier februar febbraio subat φεβρουαριου ก.พ.", 1],
  ["march mar marzo marco mars marz mart μαρτιου มี.ค.", 2], ["april apr abril avril aprile nisan απριλιου เม.ย.", 3], ["may mayo maio mai maggio mayis μαιου พ.ค.", 4],
  ["june jun junio junho juin juni giugno haziran ιουνιου มิ.ย.", 5], ["july jul julio julho juillet juli luglio temmuz ιουλιου ก.ค.", 6],
  ["august aug agosto aout agustos αυγουστου ส.ค.", 7], ["september sep sept septiembre setembro septembre settembre eylul σεπτεμβριου ก.ย.", 8],
  ["october oct octubre outubro octobre oktober ottobre ekim οκτωβριου ต.ค.", 9], ["november nov noviembre novembro novembre kasim νοεμβριου พ.ย.", 10],
  ["december dec diciembre dezembro decembre dezember dicembre aralik δεκεμβριου ธ.ค.", 11]].forEach(([ws, m]) => ws.split(" ").forEach((x) => { MONTHS[x] = m; }));
const MONTH_ALT = Object.keys(MONTHS).sort((a, b) => b.length - a.length).map((x) => x.replace(/\./g, "\\.")).join("|");
const DAY_LIST = "(\\d{1,2})((?:\\s*(?:[-–&,/]|and|y|e|et|und|ve|και|και)\\s*\\d{1,2})*)";
const DATE_DM = new RegExp(`(?<![\\d\\p{L}])${DAY_LIST}\\s*(?:de\\s+|of\\s+)?(${MONTH_ALT})(?![\\p{L}])`, "giu");
const DATE_MD = new RegExp(`(?<![\\p{L}])(${MONTH_ALT})\\s+(\\d{1,2})(?:st|nd|rd|th)?(?![\\d\\p{L}])`, "giu");
const DATE_NUM = /(?<!\d)(\d{1,2})[.-](\d{1,2})[.-](20\d\d)(?!\d)/g;
/** Does a headline name a date after the day it was published (in the publisher's time zone, whatever it is)? Published
 *  before 10:00 UTC, the next UTC day is already the future everywhere; later in the day, two days on. */
export function headlineFuture(title, published) {
  const p = typeof published === "number" ? published : ms(published);
  if (!isFinite(p)) return false;
  const t = prep(title), pd = new Date(p), y = pd.getUTCFullYear(), day0 = Date.UTC(y, pd.getUTCMonth(), pd.getUTCDate());
  const ahead = new Date(p).getUTCHours() < 10 ? 1 : 2, dates = [];
  const at = (d, m, yy) => { if (!(d >= 1 && d <= 31) || !(m >= 0 && m <= 11)) return; let x = Date.UTC(yy ?? y, m, d); if (yy == null && x < day0 - 180 * 864e5) x = Date.UTC(y + 1, m, d); dates.push(x); };
  for (const m of t.matchAll(DATE_DM)) { const days = [m[1], ...(m[2].match(/\d{1,2}/g) || [])].map(Number); at(Math.max(...days), MONTHS[m[3]]); }
  for (const m of t.matchAll(DATE_MD)) at(Number(m[2]), MONTHS[m[1]]);
  for (const m of t.matchAll(DATE_NUM)) at(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  return dates.some((x) => x >= day0 + ahead * 864e5);
}
/** Is this headline (and summary) a report of a power outage happening now? -> { ok, reason, cyber }.
 *  reason (when not ok): no_power_words, ad, not_grid, entertainment, market, product, planned, explainer, past,
 *  none_now, future, question. The headline decides; the summary only adds power words. */
export function classify(title, summary = "", o = {}) {
  const t = prep(title), s = prep(summary);
  const cyber = CYBER.test(t);
  let power = POWER.some((r) => r.test(t)) || (POWER.some((r) => r.test(s)) && OUTAGE_WORD.test(t)) || (!!o.utility && OUTAGE_ONLY.test(t));
  if (!power) return { ok: false, reason: "no_power_words", cyber };
  for (const [code, re] of GUARDS) if (re.test(t)) return { ok: false, reason: code, cyber };
  // a date in the headline after the day it was published: a schedule of cuts to come (any language)
  if (o.published && headlineFuture(title, o.published)) return { ok: false, reason: "planned", cyber };
  // an internet or cloud "outage" with only a summary mention of power is not a grid outage
  if (GUARDS[1][1].test(s) && !POWER.some((r) => r.test(t))) return { ok: false, reason: "not_grid", cyber };
  const hasFig = figure(title) != null;
  if (FUTURE_STRONG.test(t) && !PAST.test(t)) return { ok: false, reason: "future", cyber };
  if (FUTURE.test(t) && (!PRESENT.test(t) || PRESENT_AFTER_FUTURE.test(t)) && !hasFig) return { ok: false, reason: "future", cyber };
  if (QUESTION.test(String(title).trim()) && !hasFig && !PAST.test(t)) return { ok: false, reason: "question", cyber };
  return { ok: true, reason: "", cyber };
}

/* ---------- figures as reported ---------- */
const MULT = [
  [1e3, "k|thousand|mil|mille|milliers?|tausend|mila|tys\\.?|tysiac[ea]?|tysiecy|тыс\\.?|тысяч[иа]?|тис\\.?|тисяч[іа]?|bin|ribu|nghin|ngan|elfu|الف|ألف|آلاف|هزار|हजार|हज़ार|হাজার|ہزار"],
  [1e5, "lakhs?|लाख|লাখ|لاکھ"],
  [1e6, "millions?|million|mn|m|mio\\.?|millionen|millon(es)?|milhao|milhoes|milion(i|e|y|ow)?|milioni|mln\\.?|млн\\.?|миллион(а|ов)?|мільйон(а|ів)?|milyon|juta|trieu|مليون|ملايين"],
  [1e7, "crores?|करोड़|কোটি"],
];
const UNIT_RE = {
  customers: "customers?|clients?|clientes|usuarios?|abonnes?|kunden|clienti|utenze|utenti|klanten|aansluitingen|odbiorc\\w*|klientow|абонент\\w*|споживач\\w*|потребител\\w*|abone\\w*|pelanggan|khach hang|wateja|مشترك\\w*|उपभोक्ता\\w*|গ্রাহক\\w*|صارفین|accounts|meters|connections|unidades consumidoras|consumidores|consommateurs|electricity users|users|properties|premises",
  homes: "homes?( and businesses)?|houses|households?|residences|hogares|viviendas|casas|foyers|logements|menages|maisons|haushalte\\w*|wohnungen|famiglie|abitazioni|case|huishoudens|woningen|huizen|gospodarstw\\w*|domow|mieszkan|домов|домохозяйств\\w*|будинк\\w*|домогосподарств\\w*|квартир\\w*|hane|konut|rumah|ho dan|ho|nyumba|منزل|منازل|بيوت|घरों|घर|বাড়ি\\w*|گھر\\w*|domicilios|residencias|imoveis|residencias",
  people: "people|persons|residents|inhabitants|personas|habitantes|vecinos|pessoas|moradores|habitants|personnes|menschen|einwohner\\w*|personen|bewohner\\w*|persone|abitanti|mensen|inwoners|osob|mieszkanc\\w*|людей|человек|жител\\w*|мешканц\\w*|людини|kisi|vatandas|orang|warga|penduduk|nguoi|watu|شخص|أشخاص|اشخاص|مواطن\\w*|نسمة|लोगों|लोग|মানুষ|لوگ\\w*|افراد",
};
const NUM = "(?<num>\\d{1,3}(?:[,. \\u00a0\\u202f']\\d{3})+|\\d+(?:[.,]\\d+)?)";
const PCT = "\\+?(?!\\s*(?:%|percent|per cent|por ciento|pour cent|prozent|per cento|procent|процент|відсот|yuzde|persen|phan tram))";
const MULT_ALT = MULT.map(([, a]) => a).join("|");
const FIG_RE = rx(`(?<![$€£¥₹\\d.,])${NUM}${PCT}\\s*(?:(?<mult>${MULT_ALT})${E})?\\s*(?:[\\p{L}&'-]+\\s+){0,3}?(?:(?<c>${UNIT_RE.customers})|(?<h>${UNIT_RE.homes})|(?<p>${UNIT_RE.people}))${E}`, "giu");
const UNSTATED_RE = rx(`(?<![$€£¥₹\\d.,])${NUM}${PCT}\\s*(?:(?<mult>${MULT_ALT})${E})?\\s+(?:(?:still|are|remain(?:ed)?|were|now|left|currently|remain)\\s+)?(?:without (?:power|electricity)|in the dark|lost power|sin (?:luz|energia|electricidad)|sans (?:electricite|courant)|ohne strom|senza (?:luce|corrente)|zonder stroom|bez pradu|без (?:света|світла|электричества|електроенергії))`, "giu");
const CJK_RE = /(\d+(?:\.\d+)?)\s*(万|萬|만)\s*(\d+)?\s*(戸|軒|世帯|户|戶|家庭|人|名|명|가구|세대|호)|(\d[\d,]*)\s*(戸|軒|世帯|户|戶|가구|세대|명|人)/gu;
const NEAR_BAD = rx("killed|dead|died|deaths?|death toll|injured|hurt|evacuat\\w*|displaced|rescued|arrested|homeless|fatalit\\w*|muertos?|fallecid\\w*|heridos?|evacuad\\w*|morts?|blesses|tote|verletzt\\w*|morti|feriti|zabit\\w*|ofiar\\w*|погиб\\w*|загин\\w*|поранен\\w*|ранен\\w*|olu|yarali|قتلى|मौत|meninggal|死者|사망|employees|workers|staff|jobs|students|passengers|fans");
const CJK_UNIT = { 戸: "homes", 軒: "homes", 世帯: "homes", 户: "homes", 戶: "homes", 家庭: "homes", 가구: "homes", 세대: "homes", 호: "homes", 人: "people", 名: "people", 명: "people" };
/** "120,000" "10.000" "1,2" + a multiplier word -> a number (null when it is not a whole count). */
export function parseCount(raw, mult = "") {
  let s = String(raw).replace(/[  ' ]/g, (c) => (c === " " || c === " " || c === " " || c === "'" ? "," : c));
  const m = mult ? (MULT.find(([, a]) => rx(`^(?:${a})$`).test(fold(mult))) || [1])[0] : 1;
  let n;
  if (/^\d{1,3}([,.]\d{3})+$/.test(s)) n = Number(s.replace(/[,.]/g, ""));
  else if (/^\d+[.,]\d+$/.test(s)) n = Number(s.replace(",", "."));
  else n = Number(s.replace(/[,.]/g, ""));
  if (!isFinite(n)) return null;
  n = Math.round(n * m);
  return n >= 1 && n <= 2e9 ? n : null;
}
/** Every figure in a text: [{ n, unit, at }]. The unit is the word the text uses (never converted). */
export function figures(text, needPower = false) {
  const t = prep(text), out = [];
  const far = (i, len) => needPower && !POWER.some((r) => r.test(t.slice(Math.max(0, i - 70), i + len + 70))) && !PRESENT.test(t.slice(Math.max(0, i - 70), i + len + 70));
  const bad = (i, len) => far(i, len) || NEAR_BAD.test(t.slice(Math.max(0, i - 28), i)) || NEAR_BAD.test(t.slice(i + len, i + len + 28).split(/[,;|]/)[0]);
  for (const m of t.matchAll(FIG_RE)) {
    const n = parseCount(m.groups.num, m.groups.mult || ""), unit = m.groups.c ? "customers" : m.groups.h ? "homes" : "people";
    if (n != null && !bad(m.index, m[0].length)) out.push({ n, unit, at: m.index });
  }
  for (const m of t.matchAll(UNSTATED_RE)) {
    const n = parseCount(m.groups.num, m.groups.mult || "");
    if (n != null && !out.some((f) => f.at === m.index) && !bad(m.index, m[0].length)) out.push({ n, unit: "unstated", at: m.index });
  }
  for (const m of String(asciiDigits(text)).matchAll(CJK_RE)) {
    let n, unit;
    if (m[2]) { n = Math.round(Number(m[1]) * 1e4 + (Number(m[3]) || 0)); unit = CJK_UNIT[m[4]]; }
    else { n = Number(String(m[5]).replace(/,/g, "")); unit = CJK_UNIT[m[6]]; }
    const after = String(text).slice(m.index + m[0].length, m.index + m[0].length + 6);
    const around = String(asciiDigits(text)).slice(Math.max(0, m.index - 20), m.index + m[0].length + 20);
    if (n >= 1 && n <= 2e9 && unit && !/死|亡|負傷|伤|傷|사망|부상|숨져|避難|대피/.test(after) && (!needPower || /停電|停电|斷電|断电|정전/.test(around))) out.push({ n, unit, at: m.index });
  }
  return out;
}
/** The figure a report states: the largest in the headline, else in the summary; a stated unit beats "unstated". A
 *  headline cut short by the index ("…" or "...") can have lost its largest figure: then only the summary counts. */
export function figure(title, summary = "") {
  const cut = /(\.\.\.|…)\s*$/.test(String(title || ""));
  for (const text of cut ? [summary] : [title, summary]) {
    const f = figures(text, text === summary);
    if (!f.length) continue;
    const known = f.filter((x) => x.unit !== "unstated"), pool = known.length ? known : f;
    const best = pool.sort((a, b) => b.n - a.n)[0];
    return { n: best.n, unit: best.unit };
  }
  return null;
}

/* ---------- cause words as reported ---------- */
export const CAUSES = [
  ["cyberattack", CYBER],
  ["sabotage", w("sabotage|sabotaje|sabotaggio|sabotaz|саботаж\\w*|диверси\\w*|sabotaj|تخريب")],
  ["missile", w("missiles?|ракет\\w*|صاروخ\\w*|misil(es)?")],
  ["drone", w("drones?|дрон\\w*|shahed|шахед\\w*|беспилотник\\w*|безпілотник\\w*|مسيرة|مسيّرة")],
  ["shelling", w("shelling|обстріл\\w*|обстрел\\w*|bombard\\w*")],
  ["attack", w("(?<!heart )attacks?|attacked|ataques?|attaques?|angriffs?|attacc(o|hi)|atak\\w*|атак\\w*|удар\\w*|saldiri\\w*|هجوم|هجمات|हमला|serangan|攻撃|공격|tan cong|shambulio")],
  ["strike", w("strikes?|huelga|greve|streik|sciopero|strajk|grev")],
  ["theft", w("theft|stolen|cable thieves|robo de cables?|vol de cuivre|vol de cables?|кража|крадіжк\\w*|سرقة")],
  ["vandalism", w("vandal\\w*|vandalismo")],
  ["storm", w("storms?|tormentas?|temporal|tempete|orages?|sturm|unwetter|tempesta|maltempo|burz[ay]|шторм\\w*|бур[яі]\\w*|негода|firtina|عاصفة|तूफान|badai|dhoruba|bomb cyclone|atmospheric river|nor'easter|blizzard")],
  ["hurricane", w("hurricanes?|huracan|ouragan|cyclones?|ciclon|typhoons?|tifon|台風|台风|颱風|태풍|tufani")],
  ["wind", w("winds?|windy|gusts?|viento|vent|vento|wiatr|ветер|вітер|ruzgar|رياح|angin|強風|강풍")],
  ["snow", w("snow\\w*|nieve|neige|schnee|neve|snieg|снег\\w*|сніг\\w*|雪|폭설")],
  ["ice", w("ice storm|icing|freezing rain|hielo|verglas|glatteis|ghiaccio|gololedica|гололед\\w*|ожеледиц\\w*")],
  ["heat", w("heat|heatwaves?|heat wave|extreme heat|high temperatures|ola de calor|canicule|hitzewelle|ondata di caldo|upal\\w*|жар[аы]|спек[аи]|sicak hava|موجة حر|गर्मी|猛暑|폭염|nang nong")],
  ["rain", w("rain(s|fall|storms?)?|heavy rain|lluvias?|pluies?|regen|pioggia|deszcz\\w*|ливн\\w*|злив\\w*|yagmur|أمطار|बारिश|hujan|大雨|豪雨|폭우|mua|mvua")],
  ["flood", w("flood\\w*|inundaci\\w*|inondation\\w*|hochwasser|uberschwemmung\\w*|alluvion\\w*|powodz\\w*|паводок|наводнени\\w*|повін\\w*|فيضان\\w*|बाढ़|banjir|洪水|lu lut|mafuriko")],
  ["lightning", w("lightning|rayos?|foudre|blitz\\w*|fulmin\\w*|piorun\\w*|молни\\w*|блискавк\\w*|yildirim|صاعقة|petir|落雷|낙뢰|set danh")],
  ["tree", w("trees?|arbol(es)?|arbres?|baum|baume|alber[oi]|drzew\\w*|дерев\\w*|agac|شجرة|pohon|倒木")],
  ["wildfire", w("wildfires?|bushfires?|forest fires?|incendio forestal|incendie|waldbrand|incendi|pozar\\w*|пожар\\w*|yangin|حريق|आग|kebakaran|山火事|산불")],
  ["fire", w("(a |the )?fire (at|in|broke out|damaged|destroyed)|blaze|incendio en|feuer in|brand in|火災|화재")],
  ["earthquake", w("earthquakes?|sismo|terremoto|seisme|erdbeben|trzesienie ziemi|землетрус\\w*|deprem|زلزال|भूकंप|gempa|地震|지진|dong dat")],
  ["fault", w("faults?|faulty|technical (fault|problem|failure|issue)|equipment failure|averias?|defaillance|panne technique|technische storung|defekt|guasto|збій|сбой|ariza|عطل|خلل|तकनीकी खराबी|故障|고장")],
  ["transformer", w("transformers?|transformador(es)?|transformateurs?|trafo|transformator\\w*|трансформатор\\w*|محول|ट्रांसफार्मर|変圧器|변압기|may bien ap")],
  ["substation", w("substations?|subestacion(es)?|poste source|umspannwerk|cabina primaria|podstacj\\w*|подстанц\\w*|підстанц\\w*|trafo merkezi|सबस्टेशन|gardu induk|変電所|변전소|tram bien ap")],
  ["cable", w("cables?|cabos?|kabel\\w*|cav[oi]|кабел\\w*|kablo")],
  ["accident", w("(car|truck|vehicle|driver|crash) (\\w+ ){0,3}(hit|hits|into|struck|strikes) (a |the )?(power |utility )?poles?|accidente|accident")],
  ["excavation", w("excavator|digging|dig-in|construction crew|excavadora|pelleteuse|bagger")],
  ["animal", w("squirrels?|birds?|animals?|snakes?|possums?|raccoons?|ardilla|oiseau")],
  ["overload", w("overload\\w*|high demand|record demand|sobrecarga|surcharge|uberlast\\w*|sovraccaric\\w*|перегруз\\w*")],
  ["shortage", w("fuel shortages?|shortage of (fuel|gas|generation|power)|generation (deficit|shortfall)|deficit de generacion|falta de combustible|deficit de (generacion|potencia)|penurie de|дефицит мощност\\w*|дефіцит потужност\\w*")],
  ["load shedding", w("(outage|power cut|blackout|shutdown) schedules?|load ?shedding|delestages?|deslastre|racionamiento|rationing|rotating outages|rolling blackouts?|cortes rotativos|графік\\w* відключен\\w*|відключення за графіком|лимитировани\\w*|लोड शेडिंग|লোডশেডিং|لوڈشیڈنگ|لوڈ شیڈنگ|تخفيف الأحمال|pemadaman bergilir|mgao")],
  ["grid failure", w("(grid|system|network) (collapse[sd]?|collapsing|failure)|colapso|black start|desconexion del sistema|zusammenbruch")],
];
/** Cause words a report uses, in English, as reported (never inferred; translation only). */
export function causeWords(title, summary = "") {
  const t = `${prep(title)} | ${prep(summary)}`, out = [];
  const noCyber = t.replace(CYBER_G, " "), noLightning = t.replace(rx("lightning strikes?", "giu"), " ");
  for (const [word, re] of CAUSES) if (re.test(word === "attack" ? noCyber : word === "strike" ? noLightning : t)) out.push(word);
  if (out.includes("wildfire")) { const i = out.indexOf("fire"); if (i >= 0) out.splice(i, 1); }
  return out.slice(0, 8);
}
const CYBER_G = new RegExp(CYBER.source, "giu");

/* ---------- places ---------- */
const SUB = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Thai}\p{Script=Hebrew}]/u;
const ARABIC = /\p{Script=Arabic}/u, BENGALI = /\p{Script=Bengali}/u;
const NOT_COUNTRY_NAME = new Set(["Georgia", "Turkey"]);   // the US state and the bird are far more common in power news
/** Compile the gazetteer: places, utilities (their service area) and countries (with names in other languages). */
export function gazetteer(cfg = {}) {
  const ents = [], centre = (cc) => (COUNTRIES[cc] ? { name: COUNTRIES[cc][0], lat: COUNTRIES[cc][1], lng: COUNTRIES[cc][2] }
    : (cfg.country_centres || {})[cc] ? { name: cfg.country_centres[cc][0], lat: cfg.country_centres[cc][1], lng: cfg.country_centres[cc][2] } : null);
  const add = (alias, e) => {
    let a = String(alias || "").trim(); if (a.length < 2) return;
    let mode = "word";
    if (a.endsWith("*")) { mode = "prefix"; a = a.slice(0, -1); }
    else if (SUB.test(a)) mode = "sub";
    else if (BENGALI.test(a)) mode = "prefix";
    else if (ARABIC.test(a)) mode = "arabic";
    const f = prep(a); if (f.length < 2) return;
    ents.push({ ...e, alias: f, mode, re: mode === "arabic" ? new RegExp(`(?<![\\p{L}])(?:[وبلفك]|ال|وال|بال|لل)?${f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\p{L}])`, "u") : null });
  };
  // a place's own name is an alias too (Cali, Sofia, Guatemala City ...), without a "(qualifier)", unless it is ambiguous
  const ambiguous = new Set(cfg.ambiguous || []), multi = new Set(cfg.multi_area_utilities || []);
  for (const p of cfg.places || []) {
    if (!Array.isArray(p) || p.length < 6 || !/^[A-Z]{2}$/.test(p[1])) continue;
    const [name, cc, lat, lng, kind, ...aliases] = p;
    const e = { kind: kind === "city" ? "city" : "region", country: cc, region: kind === "city" ? "" : name, place: name, lat, lng };
    const own = String(name).replace(/\s*\([^)]*\)\s*$/, "").trim();
    const names = ambiguous.has(name) || aliases.some((a) => prep(String(a).replace(/\*$/, "")) === prep(own)) ? aliases : [own, ...aliases];
    for (const a of names) add(a, e);
  }
  for (const u of cfg.utilities || []) {
    if (!Array.isArray(u) || u.length < 6 || !/^[A-Z]{2}$/.test(u[1])) continue;
    const [name, cc, area, lat, lng, ...aliases] = u;
    for (const a of aliases) add(a, { kind: "utility", utility: name, country: cc, region: area, place: area, lat, lng, multi: multi.has(name) });
  }
  const ccs = new Set([...Object.keys(COUNTRIES), ...Object.keys(cfg.countries || {}), ...Object.keys(cfg.country_centres || {})]);
  for (const cc of ccs) {
    const c = centre(cc); if (!c) continue;
    const e = { kind: "country", country: cc, region: "", place: c.name, lat: c.lat, lng: c.lng };
    if (COUNTRIES[cc] && !NOT_COUNTRY_NAME.has(COUNTRIES[cc][0])) add(COUNTRIES[cc][0], e);
    for (const a of (cfg.countries || {})[cc] || []) add(a, e);
  }
  return ents;
}
const LETTER = /[\p{L}\p{N}]/u;
function matches(text, ents) {
  const out = [];
  for (const e of ents) {
    if (e.mode === "arabic") { const m = e.re.exec(text); if (m) out.push({ e, at: m.index, end: m.index + m[0].length }); continue; }
    for (let i = text.indexOf(e.alias); i >= 0; i = text.indexOf(e.alias, i + 1)) {
      const end = i + e.alias.length;
      if (e.mode !== "sub") {
        if (i > 0 && LETTER.test(text[i - 1])) continue;
        if (e.mode === "word" && end < text.length && LETTER.test(text[end])) continue;
      }
      out.push({ e, at: i, end }); break;
    }
  }
  // "Northern Ireland" is not also "Ireland"; "New Mexico" is not also "Mexico": drop matches inside a longer one
  return out.filter((m) => !out.some((o) => o !== m && o.at <= m.at && o.end >= m.end && o.end - o.at > m.end - m.at));
}
const RANK = { city: 0, region: 1 };
/** Where a report is: the most specific place it names (in its utility's or its named country when it names one), else
 *  the utility's service area, else a country it names. The headline first, the summary only when the headline names
 *  nothing. -> { country, region, place, lat, lng, how, utility } | null. Always approximate (the centre of the place). */
export function locate(title, summary, ents) {
  for (const text of [prep(title), prep(summary)]) {
    if (!text) continue;
    const ms_ = matches(text, ents); if (!ms_.length) continue;
    const util = ms_.filter((m) => m.e.kind === "utility").sort((a, b) => a.at - b.at)[0];
    // with two countries named, the one after "in", "of", "across" is where the outage is ("Russia leaves five regions of Ukraine without power")
    // a country right before an attack verb is the actor ("Russia attacked Ukraine's energy"): ranked last; one with a
    // possessive energy word after it is the place ("Ukraine's energy infrastructure")
    const after = (m) => text.slice(m.end, m.end + 40);
    const actor = (m) => /^\s*(has |have |had )?(attack\w*|strikes?|struck|shell\w*|bomb\w*|launch\w*|fired|hit|атакувал\w*|атакує|атакует|обстріля\w*|обстреля\w*|вдарил\w*|ударил\w*)(?![\p{L}])/u.test(after(m));
    const owns = (m) => /^'s?\s+(energy|power|grid|electric\w*)/.test(after(m));
    const prep_ = (m) => (owns(m) ? 0 : actor(m) ? 3 : /(^|\s)(in|of|across|throughout|en|de|du|da|do|in|im|nel|w|в|у|по|na)\s+(the\s+)?$/u.test(text.slice(Math.max(0, m.at - 14), m.at)) ? 1 : 2);
    const cos = ms_.filter((m) => m.e.kind === "country").sort((a, b) => prep_(a) - prep_(b) || a.at - b.at);
    let places = ms_.filter((m) => m.e.kind === "city" || m.e.kind === "region");
    // a utility's own country decides; a named country only breaks ties ("Valencia, Venezuela"), since a country word is
    // often the actor ("Russian shelling in Zaporizhzhia")
    if (util) places = places.filter((m) => m.e.country === util.e.country);
    // three or more regions of one country named in the same text: the report is about the country, not its first region
    const perCc = new Map(); for (const m of places) (perCc.get(m.e.country) || perCc.set(m.e.country, new Set()).get(m.e.country)).add(m.e.place);
    const wide = [...perCc].find(([, set]) => set.size >= 3);
    if (wide) { const ce = ents.find((e) => e.kind === "country" && e.country === wide[0]); if (ce) return out(ce, util); }
    const named = new Set(cos.filter((m) => prep_(m) < 3).map((m) => m.e.country)), inNamed = (m) => (named.has(m.e.country) ? 0 : 1);
    places.sort((a, b) => inNamed(a) - inNamed(b) || RANK[a.e.kind] - RANK[b.e.kind] || a.at - b.at);
    let pick = places[0] || util || cos[0];
    // "Valencia, Venezuela": a place outside the country named right after it is that country, not the place
    if (pick && pick !== util && (pick.e.kind === "city" || pick.e.kind === "region") && !named.has(pick.e.country)) { const c = cos.find((m) => m.at >= pick.end && m.at - pick.end <= 3); if (c) pick = c; }
    if (!pick) continue;
    // a utility that serves several areas (Duke Energy, AEP ...) and no named place: the country, not one of its areas
    if (pick === util && util.e.multi) { const ce = ents.find((e) => e.kind === "country" && e.country === util.e.country); if (ce) return out(ce, util); }
    return out(pick.e, util);
  }
  return null;
  function out(e, util) {
    return { country: e.country, region: str(e.region, 80), place: str(e.place, 80), lat: Math.round(e.lat * 1000) / 1000, lng: Math.round(e.lng * 1000) / 1000,
      how: e.kind === "utility" ? "utility" : e.kind === "country" ? "country" : "place", utility: util ? util.e.utility : "" };
  }
}

/* ---------- publishers' own pages ---------- */
const AGGREGATOR = /^(?:[a-z0-9-]+\.)*(google\.[a-z.]+|bing\.com|msn\.com|yahoo\.com|news\.yahoo\.co\.jp|flipboard\.com|newsbreak\.com|ground\.news|smartnews\.com|newsnow\.co\.uk|feedly\.com|inoreader\.com|apple\.news|gdeltproject\.org)$/i;
// user-generated pages are not publishers' reporting
const UGC = /^(?:[a-z0-9-]+\.)*(note\.com|medium\.com|blogspot\.com|substack\.com|wordpress\.com|tumblr\.com|reddit\.com)$/i;
/** The url if it is an https article page on a publisher's own host (no aggregator, redirect, blog platform or front
 *  page, not cut inside a percent-escape), else "". */
export function publisherUrl(u) {
  const s = String(u || "").trim();
  if (!/^https:\/\/[^\s"'<>]+$/.test(s) || s.length > 1000 || /%[0-9A-Fa-f]?$/.test(s)) return "";
  try { decodeURI(s); } catch { return ""; }
  let x; try { x = new URL(s); } catch { return ""; }
  if (x.username || x.password || x.port || AGGREGATOR.test(x.hostname) || UGC.test(x.hostname)) return "";
  if (!x.pathname || x.pathname === "/" || /^\/(index\.(html?|php))?$/.test(x.pathname)) return "";
  return x.href;
}
const host = (u) => { try { return new URL(u).hostname.replace(/^www\./, "").toLowerCase(); } catch { return ""; } };
const LANGS = { english: "en", spanish: "es", french: "fr", portuguese: "pt", german: "de", italian: "it", dutch: "nl", polish: "pl", ukrainian: "uk", russian: "ru", turkish: "tr", arabic: "ar", hindi: "hi", urdu: "ur", bengali: "bn", indonesian: "id", japanese: "ja", korean: "ko", chinese: "zh", vietnamese: "vi", swahili: "sw", greek: "el", romanian: "ro", czech: "cs", hungarian: "hu", swedish: "sv", norwegian: "no", finnish: "fi", danish: "da", hebrew: "he", thai: "th", serbian: "sr", croatian: "hr", malay: "ms", tagalog: "tl", persian: "fa", catalan: "ca", bulgarian: "bg", slovak: "sk", slovenian: "sl" };
export const langCode = (s) => { const t = String(s || "").toLowerCase().trim(); return /^[a-z]{2}(-[a-z0-9]{2,4})?$/i.test(t) ? t.slice(0, 2) : LANGS[t] || ""; };
const normTitle = (t) => prep(t).replace(/[^\p{L}\p{N}]+/gu, " ").trim();
/** A Google News headline is resolved when Bing returns the same headline on the publisher's own host. */
export function resolveGoogle(g, bingItems) {
  const gh = host(g.publisher_url), gt = normTitle(g.title);
  if (!gh || gt.length < 12) return null;
  for (const b of bingItems || []) {
    const u = publisherUrl(b.url), bh = host(u), bt = normTitle(b.title);
    if (!u || !(bh === gh || bh.endsWith("." + gh) || gh.endsWith("." + bh))) continue;
    const a = gt.slice(0, 60), c = bt.slice(0, 60);
    if (bt === gt || bt.startsWith(a) || gt.startsWith(c)) return { ...b, url: u };
  }
  return null;
}

/* ---------- reports and grouping ---------- */
/** Everything but the address: is it a current power outage, where, figure, causes. -> { ok, reason, report }. */
export function assess(raw, ents, now = Date.now(), windowH = 72) {
  const pubT = ms(raw.published);
  const title = str(raw.title, 220), t = ms(raw.published);
  if (!title) return { ok: false, reason: "no_title" };
  if (!isFinite(t)) return { ok: false, reason: "no_date" };
  if (t > now + 2 * H || t < now - windowH * H) return { ok: false, reason: "too_old" };
  const at = locate(title, raw.summary || "", ents);
  // "Oncor outage": a utility's name with "outage" in the headline is a power outage
  const tAt = at && at.utility ? locate(title, "", ents) : null;
  const c = classify(title, raw.summary || "", { utility: !!(tAt && tAt.utility), published: pubT });
  if (!c.ok) return { ok: false, reason: c.reason };
  if (!at) return { ok: false, reason: "no_place" };
  return { ok: true, reason: "", report: { title, name: str(raw.name, 80), lang: langCode(raw.lang), published: iso(t),
    ...at, figure: figure(title, raw.summary || ""), causes: causeWords(title, raw.summary || ""), cyber: c.cyber } };
}
const MON3 = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
/** The date an article's address carries (/2024/01/28/, /2024-01-28, /2024/jan/28/, 20240128 in the slug), or NaN. Indexes
 *  re-date old pages when they crawl them again; the address does not change. */
export function urlDate(u) {
  let path = ""; try { path = new URL(String(u)).pathname.toLowerCase(); } catch { return NaN; }
  const ok = (y, m, d) => (y >= 1995 && y <= 2100 && m >= 0 && m <= 11 && d >= 1 && d <= 31 ? Date.UTC(y, m, d) : NaN);
  let m = path.match(/(?:^|\/)((?:19|20)\d\d)[/-](\d{1,2})[/-](\d{1,2})(?:[/._-]|$)/);
  if (m) return ok(+m[1], +m[2] - 1, +m[3]);
  m = path.match(/(?:^|\/)((?:19|20)\d\d)\/(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\/(\d{1,2})(?:\/|$)/);
  if (m) return ok(+m[1], MON3[m[2]], +m[3]);
  m = path.match(/(?:^|[/_-])((?:19|20)\d\d)(\d\d)(\d\d)(?:[/._-]|$)/);
  if (m) return ok(+m[1], +m[2] - 1, +m[3]);
  m = path.match(/(?:^|\/)((?:19|20)\d\d)\/(\d{1,2})(?:\/|$)/);              // /2024/09/ (a month): its last day
  if (m && +m[2] >= 1 && +m[2] <= 12) return Date.UTC(+m[1], +m[2], 0);
  return NaN;
}
/** One search result -> { ok, reason, report }. raw = { title, summary, url, name, published, lang }. Only a publisher's
 *  own https article page is kept; an address dated before the window is an old article whatever the index says. */
export function toReport(raw, ents, now = Date.now(), windowH = 72) {
  const url = publisherUrl(raw.url);
  if (!url) return { ok: false, reason: "no_publisher_page" };
  const ud = urlDate(url);
  if (isFinite(ud) && ud + 864e5 < now - windowH * H) return { ok: false, reason: "too_old" };
  const a = assess(raw, ents, now, windowH);
  if (!a.ok) return a;
  return { ok: true, reason: "", report: { ...a.report, url, name: a.report.name || host(url) } };
}
const pkey = (n) => publisherKey(n) || fold(n).replace(/\s+/g, "");
// hosts that republish other publishers' articles word for word (a copy is not another publisher)
const SYNDICATOR = /^(?:[a-z0-9-]+\.)*(infoseek\.co\.jp|inshorts\.com|newsbreak\.com|headtopics\.com|dailyhunt\.in)$/i;
/** The same article on one host under another language path (/ua/ and /en/ with the same number) is one report. */
const articleKey = (u) => { try { const x = new URL(u), id = (x.pathname.match(/\d{5,}/g) || []).sort((a, b) => b.length - a.length)[0]; return id ? `${x.hostname.replace(/^www\./, "")}#${id}` : ""; } catch { return ""; } };
const kmBetween = (a, b) => { const r = Math.PI / 180, dl = (b.lat - a.lat) * r, dg = (b.lng - a.lng) * r;
  const h = Math.sin(dl / 2) ** 2 + Math.cos(a.lat * r) * Math.cos(b.lat * r) * Math.sin(dg / 2) ** 2; return 12742 * Math.asin(Math.sqrt(h)); };
// how near two reported places must be to be one outage: two cities (Reno, Sparks) 50 km; a region and anything in it
// (Washoe County / Reno and Nevada, Port Lincoln and the Eyre Peninsula) 300 km
export const NEAR_CITY_KM = 50, NEAR_REGION_KM = 300;
const nearEnough = (a, b) => kmBetween(a, b) <= (a.region || b.region ? NEAR_REGION_KM : NEAR_CITY_KM);
const better = (a, b) => (!a ? b : !b ? a : (b.n > a.n || (b.n === a.n && a.unit === "unstated" && b.unit !== "unstated")) ? b : a);
/** Reports of the same outage within group_hours of its other reports are one reported outage: same country AND the same
 *  place, or both below country level with centres near enough (nearEnough; the nearest such outage wins). Earlier outages (prev
 *  items) keep their id; a publisher is listed once per outage (its earliest report); the same article under another
 *  language path, and a syndicator's word-for-word copy, are not another publisher. */
export function group(prevItems, reports, now = Date.now(), cfg = {}) {
  const win = (cfg.window_hours || 72) * H, gap = (cfg.group_hours || 12) * H, max = cfg.max_items || 300;
  const items = (prevItems || []).filter((it) => it && Array.isArray(it.publishers) && it.publishers.length && ms(it.last_seen || it.first_seen) >= now - win)
    // an earlier run's publisher whose address the current rules refuse (a cut link, a blog platform) is dropped, so the file stays valid
    .map((it) => ({ ...it, publishers: it.publishers.filter((p) => p && publisherUrl(p.url) === p.url), cause_words: (it.cause_words || []).slice() })).filter((it) => it.publishers.length);
  const urls = new Set(items.flatMap((it) => it.publishers.map((p) => p.url))), ids = new Set(items.map((it) => it.id));
  const arts = new Set(items.flatMap((it) => it.publishers.map((p) => articleKey(p.url)).filter(Boolean)));
  const countryLevel = (x) => !!COUNTRIES[x.country] && fold(x.place) === fold(COUNTRIES[x.country][0]);
  const span = (it) => { const ts = it.publishers.map((p) => ms(p.published)); return [Math.min(...ts), Math.max(...ts)]; };
  for (const r of [...reports].sort((a, b) => ms(a.published) - ms(b.published))) {
    const ak = articleKey(r.url);
    if (urls.has(r.url) || (ak && arts.has(ak))) continue;
    urls.add(r.url); if (ak) arts.add(ak);
    const t = ms(r.published), key = `${r.country}|${fold(r.place)}`, inTime = (x) => { const [a, b] = span(x); return t >= a - gap && t <= b + gap; };
    let it = items.find((x) => `${x.country}|${fold(x.place)}` === key && inTime(x));
    if (!it && !countryLevel(r)) it = items.filter((x) => x.country === r.country && !countryLevel(x) && inTime(x) && nearEnough(x, r))
      .sort((a, b) => kmBetween(a, r) - kmBetween(b, r))[0];
    const pub = { name: r.name, url: r.url, title: r.title, lang: r.lang, published: r.published };
    if (!it) {
      it = { id: "", country: r.country, region: r.region, place: r.place, lat: r.lat, lng: r.lng, approx: true, figure: null, cause_words: [],
        first_seen: r.published, last_seen: r.published, publishers: [], count: 0, cyber_headline: "" };
      items.push(it);
    }
    if (it.publishers.some((p) => pkey(p.name) === pkey(r.name))) continue;
    const nt = normTitle(r.title);
    if (it.publishers.some((p) => normTitle(p.title) === nt && (SYNDICATOR.test(host(p.url)) || SYNDICATOR.test(host(r.url))))) continue;
    it.publishers.push(pub);
    it.figure = better(it.figure, r.figure ? { ...r.figure, by: r.name } : null);
    for (const c of r.causes) if (!it.cause_words.includes(c)) it.cause_words.push(c);
    if (r.cyber && !it.cyber_headline) it.cyber_headline = r.title;
  }
  for (const it of items) {
    it.publishers.sort((a, b) => ms(a.published) - ms(b.published));
    it.publishers = it.publishers.slice(0, 20);
    it.first_seen = it.publishers[0].published; it.last_seen = it.publishers[it.publishers.length - 1].published;
    it.count = it.publishers.length; it.cause_words = it.cause_words.slice(0, 8);
    if (!it.id) {
      const base = `gn-${it.country.toLowerCase()}-${slug(it.place)}-${it.first_seen.slice(0, 13).replace(/\D/g, "")}`;
      let id = base; for (let i = 2; ids.has(id); i++) id = `${base}-${i}`;
      it.id = id; ids.add(id);
    }
  }
  return items.filter((it) => ms(it.last_seen) >= now - win)
    .sort((a, b) => b.count - a.count || (a.last_seen < b.last_seen ? 1 : -1)).slice(0, max);
}

// the guards that say a headline is not a current outage (not those that only lack a word the summary had given)
const RECHECK = new Set(["planned", "future", "past", "explainer", "not_current", "none_now", "not_grid", "ad", "entertainment", "market", "product"]);
/** Earlier runs' items with the publishers the current rules reject taken out (a schedule kept before the rules knew its
 *  language stays off the map at once, not for the rest of its 72 hours). */
export function recheck(prevItems) {
  return (prevItems || []).map((it) => (it && Array.isArray(it.publishers)
    ? { ...it, publishers: it.publishers.filter((p) => p && !RECHECK.has(classify(p.title, "", { published: ms(p.published) }).reason)) } : it));
}
/** The news reports as leads for scripts/grid-analysis.mjs corroborate() (kind "news"; titles only). */
export function newsLeads(d) {
  return ((d && Array.isArray(d.items)) ? d.items : []).flatMap((it) => (it && Array.isArray(it.publishers) ? it.publishers : [])
    .map((p) => ({ seen_at: it.first_seen, published: p.published, source: p.name, title: p.title, url: p.url, via: "grid-news", country: it.country,
      lat: it.lat, lng: it.lng, how: COUNTRIES[it.country] && it.place === COUNTRIES[it.country][0] ? "country" : "place" })));
}

/** Shape check of data/grid/news.json -> list of problems (empty = fine). */
export function checkNews(d) {
  const e = [];
  if (!d || typeof d !== "object" || !Array.isArray(d.items)) return ["items must be a list"];
  if (!isFinite(ms(d.updated_at))) e.push("updated_at is not a time");
  if (d.items.length > 300) e.push(`more than 300 items (${d.items.length})`);
  const ids = new Set();
  d.items.forEach((it, i) => {
    const at = `items[${i}]`;
    if (!it || typeof it !== "object") { e.push(`${at}: not an object`); return; }
    if (!/^gn-[a-z]{2}-[a-z0-9-]+$/.test(it.id || "")) e.push(`${at}: bad id`);
    if (ids.has(it.id)) e.push(`${at}: duplicate id ${it.id}`); ids.add(it.id);
    if (!/^[A-Z]{2}$/.test(it.country || "")) e.push(`${at}: bad country`);
    if (typeof it.place !== "string" || !it.place) e.push(`${at}: no place`);
    if (!(Math.abs(it.lat) <= 90) || !(Math.abs(it.lng) <= 180)) e.push(`${at}: bad lat/lng`);
    if (it.approx !== true) e.push(`${at}: approx must be true`);
    if (it.figure !== null && !(it.figure && Number.isInteger(it.figure.n) && it.figure.n > 0 && UNITS.includes(it.figure.unit))) e.push(`${at}: bad figure`);
    if (!Array.isArray(it.cause_words) || it.cause_words.some((c) => !CAUSES.some(([w_]) => w_ === c))) e.push(`${at}: bad cause_words`);
    if (!isFinite(ms(it.first_seen))) e.push(`${at}: bad first_seen`);
    if (!Array.isArray(it.publishers) || !it.publishers.length) e.push(`${at}: no publishers`);
    else {
      if (it.count !== it.publishers.length) e.push(`${at}: count is not the number of publishers`);
      it.publishers.forEach((p, j) => {
        if (!p || !publisherUrl(p.url) || publisherUrl(p.url) !== p.url) e.push(`${at}.publishers[${j}]: url is not a publisher's own https page`);
        if (!p || !p.name || !p.title || !isFinite(ms(p.published))) e.push(`${at}.publishers[${j}]: name, title and published are required`);
      });
    }
  });
  return e;
}

/* ---------- collectors (polite: one request at a time per index, a pause between, a refusal ends that index's run) ---------- */
export function loadConfig(p = CFG_PATH) { return readJson(p, {}) || {}; }
async function fetchText(url, as = "text") {
  const r = await fetch(url, { headers: { "user-agent": UA, accept: as === "json" ? "application/json" : "application/rss+xml, application/xml, text/xml, */*" }, signal: AbortSignal.timeout(25000) });
  if (r.status === 401 || r.status === 403) throw Object.assign(new Error(`HTTP ${r.status} (refuses automated readers; not retried)`), { final: true });
  if (r.status === 429) throw Object.assign(new Error("HTTP 429 (busy; will try next run)"), { final: true });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const body = await r.text();
  return as === "json" ? JSON.parse(body) : body;
}
const entities = (s) => String(s || "").replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(+n))
  .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16))).replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
/** Bing News RSS with the publisher's name (<News:Source>) kept beside osint's parser (times: osint bingTime, US Pacific). */
export function parseBing(xml, now = Date.now()) {
  const out = [];
  for (const m of String(xml).matchAll(/<item>[\s\S]*?<\/item>/g)) {
    const it = parseBingNews(m[0], now)[0]; if (!it) continue;
    const src = (m[0].match(/<News:Source>([\s\S]*?)<\/News:Source>/i) || [])[1];
    out.push({ ...it, name: str(entities(src), 80) || it.source });
  }
  return out;
}
async function index(name, list, delay, fn, health) {
  const h = health[name] = { ok: true, error: "", requests: 0, items: 0 };
  let fails = 0;
  for (const x of list) {
    try { h.items += await fn(x); h.requests++; fails = 0; }
    catch (e) { h.requests++; h.error = str((e.cause && e.cause.code) || e.message, 90); fails++; if (e.final || fails >= 3) { h.ok = false; break; } }
    await sleep(fails ? delay * 4 : delay);   // back off after an error
  }
  if (h.error && !h.items) h.ok = false;
}

async function run(force) {
  const cfg = loadConfig(), now = Date.now(), st = readStatus(), every = Math.max(5, Number(cfg.every_minutes) || 15);
  const last = ms(st.last_grid_news_at);
  if (!force && isFinite(last) && now - last < every * 6e4) { console.log(`grid-news: ran ${Math.round((now - last) / 6e4)} min ago (every ${every} min); skipping`); return 0; }
  const prev = readJson(OUT_PATH, null) || { items: [] }, ents = gazetteer(cfg);
  const Q = (cfg.queries || []).filter((q) => q && typeof q.q === "string" && q.q.length <= 120), per = Math.max(1, Math.min(Q.length, Number(cfg.per_run) || 48));
  const cursor = Number.isInteger(prev.cursor) && prev.cursor >= 0 ? prev.cursor % Math.max(1, Q.length) : 0;
  const todo = Array.from({ length: per }, (_, i) => Q[(cursor + i) % Q.length]);
  const health = {}, google = [], bing = [], gdelt = [];
  const hl = (q) => (/^[\w-]{2,8}$/.test(q.hl || "") ? q.hl : "en"), gl = (q) => (/^[A-Z]{2}$/.test(q.gl || "") ? q.gl : "US");
  await Promise.all([
    index("google-news", todo, 1500, async (q) => {
      const items = parseGoogleNews(await fetchText(`https://news.google.com/rss/search?q=${encodeURIComponent(q.q + " when:1d")}&hl=${hl(q)}&gl=${gl(q)}&ceid=${gl(q)}:${hl(q).split("-")[0]}`));
      items.slice(0, 20).forEach((i) => google.push({ ...i, lang: hl(q), gl: gl(q) })); return items.length;
    }, health),
    index("bing-news", todo, 900, async (q) => {
      const items = parseBing(await fetchText(`https://www.bing.com/news/search?q=${encodeURIComponent(q.q)}&format=rss&qft=${encodeURIComponent('interval="7"')}&cc=${gl(q)}&setlang=${hl(q).split("-")[0]}`));
      items.slice(0, 20).forEach((i) => bing.push({ ...i, lang: hl(q) })); return items.length;
    }, health),
    index("gdelt", (cfg.gdelt_queries || []).slice(0, 4), 6000, async (q) => {
      const items = parseGdelt(await fetchText(`https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(q)}&mode=artlist&maxrecords=120&format=json&timespan=12h&sort=datedesc`, "json"));
      items.forEach((i) => gdelt.push({ ...i, name: i.source })); return items.length;
    }, health),
  ]);
  // Google News only names the publisher: look its headline up once on Bing and keep it only on the publisher's own host
  const raws = [...bing.map((b) => ({ ...b, via: "bing-news" })), ...gdelt.map((g) => ({ ...g, via: "gdelt" }))];
  const seen = new Set(raws.map((r) => publisherUrl(r.url)).filter(Boolean)), knownTitles = new Set(raws.map((r) => normTitle(r.title)));
  for (const it of prev.items || []) for (const p of it.publishers || []) { seen.add(p.url); knownTitles.add(normTitle(p.title)); }
  const cands = [], gStat = { candidates: 0, resolved: 0, unresolved: 0, already: 0 };
  for (const g of google) {
    const k = normTitle(g.title);
    if (knownTitles.has(k)) { gStat.already++; continue; }
    const r = assess({ title: g.title, summary: "", name: g.source, published: g.published, lang: g.lang }, ents, now, cfg.window_hours || 72);
    if (r.ok && g.publisher_url && !cands.some((c) => normTitle(c.title) === k)) cands.push(g);
  }
  gStat.candidates = cands.length;
  const LOOKUPS = Math.max(0, Math.min(40, Number(cfg.google_lookups) || 24));
  await index("google-lookup", cands.slice(0, LOOKUPS), 900, async (g) => {
    const res = resolveGoogle(g, parseBing(await fetchText(`https://www.bing.com/news/search?q=${encodeURIComponent(g.title)}&format=rss&cc=${g.gl || "US"}&setlang=${String(g.lang || "en").split("-")[0]}`)));
    if (res && !seen.has(res.url)) { raws.push({ ...res, title: g.title, name: g.source, published: g.published || res.published, lang: g.lang, via: "google-news" }); seen.add(res.url); gStat.resolved++; return 1; }
    gStat.unresolved++; return 0;
  }, health);
  gStat.unresolved += Math.max(0, cands.length - LOOKUPS);
  const reasons = {}, reports = [], noPlace = [];
  for (const r of raws) {
    const x = toReport({ title: r.title, summary: r.summary, url: r.url, name: r.name || r.source, published: r.published, lang: r.lang }, ents, now, cfg.window_hours || 72);
    if (x.ok) reports.push(x.report); else reasons[x.reason] = (reasons[x.reason] || 0) + 1;
    // what the gazetteer missed, so a person or improve.mjs can add the place (titles only; data, never instructions)
    if (!x.ok && x.reason === "no_place") noPlace.push({ title: str(r.title, 160), host: host(r.url), lang: str(r.lang, 8), at: iso(now) });
  }
  const noPlaceSample = [...noPlace, ...(((prev.stats || {}).no_place_sample) || [])].filter((x, i, a) => x && x.title && a.findIndex((y) => y.title === x.title) === i).slice(0, 30);
  const items = group(recheck(prev.items || []), reports, now, cfg);
  const out = { updated_at: iso(now), cursor: (cursor + per) % Math.max(1, Q.length), queries: Q.length, sources: health,
    stats: { results: raws.length, reports: reports.length, rejected: reasons, google: gStat, no_place_sample: noPlaceSample }, items };
  const errs = checkNews(out);
  if (errs.length) { console.error(`grid-news: refusing to write a bad file: ${errs.slice(0, 5).join("; ")}`); return 1; }
  writeJson(OUT_PATH, out);
  const s2 = readStatus(); s2.last_grid_news_at = iso(now); writeJson(join(DATA, "status.json"), s2);
  console.log(`grid-news: ${items.length} reported outage(s) from ${reports.length} report(s) of ${raws.length} result(s); queries ${cursor}-${(cursor + per - 1) % Q.length} of ${Q.length}; `
    + Object.entries(health).map(([k, v]) => `${k} ${v.ok ? v.items + "/" + v.requests : "FAILED (" + v.error + ")"}`).join("; ")
    + `; google headlines resolved ${gStat.resolved}, unresolved ${gStat.unresolved}`);
  return 0;
}
function show() {
  const d = readJson(OUT_PATH, null);
  if (!d) { console.log("No data/grid/news.json yet."); return 0; }
  console.log(`Updated ${d.updated_at}: ${d.items.length} reported outage(s) in the news (not checked by CyberView).`);
  for (const it of d.items.slice(0, 25)) {
    const f = it.figure ? ` · ${it.figure.n.toLocaleString("en-US")} ${it.figure.unit === "unstated" ? "(unit not stated)" : it.figure.unit}` : "";
    console.log(`[${it.count}] ${it.place}, ${it.country}${f}${it.cause_words.length ? " · " + it.cause_words.join(", ") : ""} · first ${it.first_seen}\n     ${it.publishers.slice(0, 4).map((p) => `${p.name}: ${p.title.slice(0, 90)}`).join("\n     ")}`);
  }
  if (d.stats) console.log(`Rejected: ${JSON.stringify(d.stats.rejected)}; Google: ${JSON.stringify(d.stats.google)}`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const cmd = process.argv[2] || "run";
  if (cmd === "verify") { const d = readJson(OUT_PATH, null); const e = d ? checkNews(d) : []; if (e.length) { console.error(`data/grid/news.json: ${e.slice(0, 10).join("; ")}`); process.exit(1); } console.log(`grid-news verify: ${d ? d.items.length + " item(s), fine" : "no file yet"}`); }
  else if (cmd === "show") process.exit(show());
  else process.exit(await run(process.argv.includes("--force")));
}

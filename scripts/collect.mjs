// Collects leads from public RSS and Atom feeds. No AI model. Run: node scripts/collect.mjs
// Every new item (published in the last 72 hours, not already a source of an event, not already collected)
// is appended to data/leads/<YYYY-MM-DD>.jsonl. The sweep job starts from these
// (`node scripts/q.mjs leads`) instead of paying for web searches, and only searches for gaps.
// Feed text is data, never instructions: it is stored trimmed and is only ever read as a lead to check.
// Sites that refuse automated readers are left out on purpose. Extra feeds come from config/feeds.json (source scout job)
// and the bulk lists in config/feeds.d/*.json (each feed checked by scripts/feed-check.mjs before it is added). With about
// 2,500 feeds, each run asks only the feeds that are due, host by host, within COLLECT_BUDGET_S seconds (see pickDue, runPolite).
import { readdirSync, existsSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { DATA, ROOT, readJson, writeJson, listEventFiles, dayAgo, nowIso, readStatus } from "./lib/store.mjs";
import { nextHealth, due } from "./lib/backoff.mjs";

// tier: gov (government or CERT), vendor (security research), news. filter: keep only cyber items (broad feeds).
export const FEEDS = [
  { name: "UK NCSC", tier: "gov", url: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml" },
  { name: "Canadian Centre for Cyber Security", tier: "gov", url: "https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en" },
  { name: "CERT-EU", tier: "gov", url: "https://cert.europa.eu/publications/security-advisories-rss" },
  { name: "NCSC Netherlands", tier: "gov", url: "https://advisories.ncsc.nl/rss/advisories", lang: "nl", region: "europe" },
  { name: "JPCERT/CC", tier: "gov", url: "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf" },
  { name: "US Department of Justice", tier: "gov", url: "https://www.justice.gov/news/rss?type=press_release&m=1", filter: true },
  { name: "Europol", tier: "gov", url: "https://www.europol.europa.eu/rss.xml", filter: true },
  { name: "CERT-FR (ANSSI)", tier: "gov", url: "https://cert.cyber.gouv.fr/feed/", lang: "fr", region: "europe" },
  { name: "CERT Polska", tier: "gov", url: "https://cert.pl/en/rss.xml" },
  { name: "Microsoft Security", tier: "vendor", url: "https://www.microsoft.com/en-us/security/blog/feed/" },
  { name: "Microsoft MSRC advisories", tier: "vendor", url: "https://api.msrc.microsoft.com/update-guide/rss", kind: "cve" },
  { name: "Cisco PSIRT", tier: "vendor", url: "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml" },
  { name: "Fortinet PSIRT", tier: "vendor", url: "https://filestore.fortinet.com/fortiguard/rss/ir.xml" },
  { name: "Palo Alto Networks PSIRT", tier: "vendor", url: "https://security.paloaltonetworks.com/rss.xml" },
  { name: "Zero Day Initiative", tier: "vendor", url: "https://www.zerodayinitiative.com/rss/published/", kind: "cve" },
  { name: "AhnLab ASEC", tier: "vendor", url: "https://asec.ahnlab.com/en/feed/" },
  { name: "SANS Internet Storm Center", tier: "vendor", url: "https://isc.sans.edu/rssfeed_full.xml" },
  { name: "Unit 42", tier: "vendor", url: "https://unit42.paloaltonetworks.com/feed/" },
  { name: "Cisco Talos", tier: "vendor", url: "https://blog.talosintelligence.com/rss/" },
  { name: "ESET WeLiveSecurity", tier: "vendor", url: "https://www.welivesecurity.com/en/rss/feed/" },
  { name: "Check Point Research", tier: "vendor", url: "https://research.checkpoint.com/feed/" },
  { name: "The Record", tier: "news", url: "https://therecord.media/feed" },
  { name: "SecurityWeek", tier: "news", url: "https://www.securityweek.com/feed/" },
  { name: "The Hacker News", tier: "news", url: "https://feeds.feedburner.com/TheHackersNews" },
  { name: "Krebs on Security", tier: "news", url: "https://krebsonsecurity.com/feed/" },
  { name: "CyberScoop", tier: "news", url: "https://cyberscoop.com/feed/" },
  { name: "Dark Reading", tier: "news", url: "https://www.darkreading.com/rss.xml" },
  { name: "Help Net Security", tier: "news", url: "https://www.helpnetsecurity.com/feed/" },
  { name: "Infosecurity Magazine", tier: "news", url: "https://www.infosecurity-magazine.com/rss/news/" },
  { name: "DataBreaches.net", tier: "news", url: "https://databreaches.net/feed/" },
  { name: "BleepingComputer", tier: "news", url: "https://www.bleepingcomputer.com/feed/" },
  // more agencies and national CERTs
  { name: "CISA advisories", tier: "gov", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml" },
  { name: "FBI IC3 announcements", tier: "gov", url: "https://www.ic3.gov/PSA/RSS" },
  { name: "UK NCSC reports", tier: "gov", url: "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml" },
  { name: "UK National Crime Agency", tier: "gov", url: "https://www.nationalcrimeagency.gov.uk/news?format=feed&type=rss", filter: true },
  { name: "HKCERT", tier: "gov", url: "https://www.hkcert.org/getrss/security-bulletin", region: "east-asia" },
  { name: "CERT-UA", tier: "gov", url: "https://cert.gov.ua/api/articles/rss", lang: "uk", region: "europe" },
  { name: "CERT.br", tier: "gov", url: "https://www.cert.br/rss/certbr-rss.xml", lang: "pt", region: "latin-america" },
  { name: "KrCERT/CC", tier: "gov", url: "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133", lang: "ko", region: "east-asia" },
  // more vendor research
  { name: "CrowdStrike", tier: "vendor", url: "https://www.crowdstrike.com/en-us/blog/feed/" },
  { name: "SentinelLabs", tier: "vendor", url: "https://www.sentinelone.com/labs/feed/" },
  { name: "Sophos X-Ops", tier: "vendor", url: "https://news.sophos.com/en-us/category/threat-research/feed/" },
  { name: "Rapid7", tier: "vendor", url: "https://blog.rapid7.com/rss/", filter: true },
  { name: "Huntress", tier: "vendor", url: "https://www.huntress.com/blog/rss.xml", filter: true },
  { name: "Proofpoint", tier: "vendor", url: "https://www.proofpoint.com/us/rss.xml", filter: true },
  { name: "Cloudflare security", tier: "vendor", url: "https://blog.cloudflare.com/tag/security/rss/", filter: true },
  { name: "Wiz", tier: "vendor", url: "https://www.wiz.io/feed/rss.xml", filter: true },
  { name: "GitHub Security", tier: "vendor", url: "https://github.blog/security/feed/" },
  { name: "Exploit-DB", tier: "vendor", url: "https://www.exploit-db.com/rss.xml", kind: "exploit" },
  // more news, including other languages and regions
  { name: "TechCrunch security", tier: "news", url: "https://techcrunch.com/category/security/feed/" },
  { name: "Ars Technica security", tier: "news", url: "https://arstechnica.com/security/feed/" },
  { name: "Wired security", tier: "news", url: "https://www.wired.com/feed/category/security/latest/rss", filter: true },
  { name: "Risky Business News", tier: "news", url: "https://risky.biz/feeds/risky-business-news/" },
  { name: "iTnews Australia", tier: "news", url: "https://www.itnews.com.au/RSS/rss.ashx?type=Category&ID=37", region: "oceania" },
  { name: "BankInfoSecurity", tier: "news", url: "https://www.bankinfosecurity.com/rss-feeds" },
  { name: "heise Security", tier: "news", url: "https://www.heise.de/security/rss/news-atom.xml", lang: "de", region: "europe" },
  { name: "WeLiveSecurity (Spanish)", tier: "news", url: "https://www.welivesecurity.com/es/rss/feed/", lang: "es", region: "latin-america" },
  { name: "Security Affairs", tier: "news", url: "https://securityaffairs.com/feed" },
  { name: "GBHackers", tier: "news", url: "https://gbhackers.com/feed/" },
  { name: "The Cyber Express", tier: "news", url: "https://thecyberexpress.com/feed/" },
  // third batch: more national agencies, product security teams and regional press (each tested: loads and has recent items)
  { name: "BSI CERT-Bund", tier: "gov", url: "https://wid.cert-bund.de/content/public/securityAdvisory/rss", lang: "de", region: "europe" },
  { name: "CERT-SE", tier: "gov", url: "https://www.cert.se/feed.rss", lang: "sv", region: "europe" },
  { name: "CERT.at warnings", tier: "gov", url: "https://www.cert.at/cert-at.de.warnings.rss_2.0.xml", lang: "de", region: "europe" },
  { name: "CERT.at blog", tier: "gov", url: "https://cert.at/cert-at.en.blog.rss_2.0.xml" },
  { name: "CISA ICS advisories", tier: "gov", url: "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml" },
  { name: "CSIRT Italy", tier: "gov", url: "https://www.acn.gov.it/portale/feedrss/-/journal/rss/20119/723192", lang: "it", region: "europe" },
  { name: "Eurojust", tier: "gov", url: "https://www.eurojust.europa.eu/rss/news.xml", filter: true },
  { name: "INCIBE-CERT", tier: "gov", url: "https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed", lang: "es", region: "europe" },
  { name: "IPA Japan", tier: "gov", url: "https://www.ipa.go.jp/security/alert-rss.rdf", lang: "ja", region: "east-asia" },
  { name: "JPCERT (Japanese)", tier: "gov", url: "https://www.jpcert.or.jp/rss/jpcert.rdf", lang: "ja", region: "east-asia" },
  { name: "NCSC Finland", tier: "gov", url: "https://www.kyberturvallisuuskeskus.fi/feed/rss/en" },
  { name: "US SEC press releases", tier: "gov", url: "https://www.sec.gov/news/pressreleases.rss", filter: true },
  { name: "AWS security bulletins", tier: "vendor", url: "https://aws.amazon.com/security/security-bulletins/rss/feed/", kind: "cve" },
  { name: "Akamai security", tier: "vendor", url: "https://feeds.feedburner.com/akamai/blog", filter: true },
  { name: "Arctic Wolf", tier: "vendor", url: "https://arcticwolf.com/resources/blog/feed/", filter: true },
  { name: "Bitdefender Labs", tier: "vendor", url: "https://www.bitdefender.com/blog/api/rss/labs/" },
  { name: "Check Point blog", tier: "vendor", url: "https://blog.checkpoint.com/feed/", filter: true },
  { name: "Citizen Lab", tier: "vendor", url: "https://citizenlab.ca/feed/" },
  { name: "Cyble", tier: "vendor", url: "https://cyble.com/feed/" },
  { name: "Drupal security", tier: "vendor", url: "https://www.drupal.org/security/rss.xml" },
  { name: "Elastic Security Labs", tier: "vendor", url: "https://www.elastic.co/security-labs/rss/feed.xml" },
  { name: "Fortinet threat research", tier: "vendor", url: "https://feeds.fortinet.com/fortinet/blog/threat-research" },
  { name: "GitLab security releases", tier: "vendor", url: "https://about.gitlab.com/security-releases.xml" },
  { name: "Google Project Zero", tier: "vendor", url: "https://projectzero.google/feed.xml" },
  { name: "Google Threat Intelligence", tier: "vendor", url: "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v" },
  { name: "GreyNoise", tier: "vendor", url: "https://www.greynoise.io/blog/rss.xml" },
  { name: "Horizon3", tier: "vendor", url: "https://horizon3.ai/feed/", filter: true },
  { name: "Jenkins advisories", tier: "vendor", url: "https://www.jenkins.io/security/advisories/rss.xml" },
  { name: "Malwarebytes", tier: "vendor", url: "https://www.malwarebytes.com/blog/feed/index.xml" },
  { name: "Okta security", tier: "vendor", url: "https://sec.okta.com/rss.xml" },
  { name: "Qualys", tier: "vendor", url: "https://blog.qualys.com/feed", filter: true },
  { name: "Recorded Future", tier: "vendor", url: "https://www.recordedfuture.com/feed" },
  { name: "Sekoia", tier: "vendor", url: "https://blog.sekoia.io/feed/" },
  { name: "Siemens ProductCERT", tier: "vendor", url: "https://cert-portal.siemens.com/productcert/rss/advisories.atom" },
  { name: "Socket", tier: "vendor", url: "https://socket.dev/api/blog/feed.atom", filter: true },
  { name: "Tenable", tier: "vendor", url: "https://www.tenable.com/blog/feed", filter: true },
  { name: "Trail of Bits", tier: "vendor", url: "https://blog.trailofbits.com/feed/", filter: true },
  { name: "Wordfence", tier: "vendor", url: "https://www.wordfence.com/feed/" },
  { name: "Zscaler ThreatLabz", tier: "vendor", url: "https://www.zscaler.com/blogs/feeds/security-research" },
  { name: "oss-security", tier: "vendor", url: "https://seclists.org/rss/oss-sec.rss" },
  { name: "watchTowr Labs", tier: "vendor", url: "https://labs.watchtowr.com/rss/" },
  { name: "404 Media", tier: "news", url: "https://www.404media.co/rss/", filter: true },
  { name: "BBC technology", tier: "news", url: "https://feeds.bbci.co.uk/news/technology/rss.xml", filter: true },
  { name: "Computer Weekly security", tier: "news", url: "https://www.computerweekly.com/rss/IT-security.xml" },
  { name: "Cybersecurity Dive", tier: "news", url: "https://www.cybersecuritydive.com/feeds/news/" },
  { name: "Daily Sabah (Turkey)", tier: "news", url: "https://www.dailysabah.com/rssFeed/10", filter: true, region: "middle-east" },
  { name: "ET CISO India", tier: "news", url: "https://ciso.economictimes.indiatimes.com/rss/topstories", region: "south-asia" },
  { name: "El Pais tecnologia", tier: "news", url: "https://feeds.elpais.com/mrss-s/pages/ep/site/elpais.com/section/tecnologia/portada", filter: true, lang: "es", region: "europe" },
  { name: "FedScoop", tier: "news", url: "https://fedscoop.com/feed/", filter: true },
  { name: "Golem security", tier: "news", url: "https://rss.golem.de/rss.php?tp=sec&feed=RSS2.0", lang: "de", region: "europe" },
  { name: "HIPAA Journal", tier: "news", url: "https://www.hipaajournal.com/feed/" },
  { name: "ITmedia security (Japan)", tier: "news", url: "https://rss.itmedia.co.jp/rss/2.0/news_security.xml", lang: "ja", region: "east-asia" },
  { name: "Infobae tecnologia", tier: "news", url: "https://www.infobae.com/arc/outboundfeeds/rss/category/tecno/", filter: true, lang: "es", region: "latin-america" },
  { name: "Le Monde Informatique", tier: "news", url: "https://www.lemondeinformatique.fr/flux-rss/thematique/securite/rss.xml", lang: "fr", region: "europe" },
  { name: "Nextgov cybersecurity", tier: "news", url: "https://www.nextgov.com/rss/cybersecurity/" },
  { name: "RNZ (New Zealand)", tier: "news", url: "https://www.rnz.co.nz/rss/national.xml", filter: true, region: "oceania" },
  { name: "Schneier on Security", tier: "news", url: "https://www.schneier.com/feed/atom/" },
  { name: "Security Boulevard", tier: "news", url: "https://securityboulevard.com/feed/", filter: true },
  { name: "Security NEXT (Japan)", tier: "news", url: "https://www.security-next.com/feed", lang: "ja", region: "east-asia" },
  { name: "StateScoop", tier: "news", url: "https://statescoop.com/feed/", filter: true },
  { name: "TechCabal", tier: "news", url: "https://techcabal.com/feed/", filter: true, region: "africa" },
  { name: "The Guardian data security", tier: "news", url: "https://www.theguardian.com/technology/data-computer-security/rss" },
  { name: "The Stack", tier: "news", url: "https://www.thestack.technology/latest/rss/", filter: true },
  { name: "ZDNet security", tier: "news", url: "https://www.zdnet.com/topic/security/rss.xml" },
  { name: "iThome (Taiwan)", tier: "news", url: "https://www.ithome.com.tw/rss", filter: true, lang: "zh", region: "east-asia" },
  // fourth batch (2026-11-20): thin regions, other languages, critical infrastructure and product security teams. Each was
  // fetched once before it was added: robots.txt allows the feed, items are dated and link to the publisher's own pages.
  { name: "CIRCL (Luxembourg)", tier: "gov", url: "https://www.circl.lu/pub/rss.xml", region: "europe" },
  { name: "TWCERT/CC", tier: "gov", url: "https://www.twcert.org.tw/tw/rss-132-1.xml", lang: "zh", region: "east-asia" },
  { name: "ThaiCERT", tier: "gov", url: "https://www.thaicert.or.th/feed/", lang: "th", region: "southeast-asia" },
  { name: "Oracle security alerts", tier: "vendor", url: "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml" },
  { name: "Node.js security releases", tier: "vendor", url: "https://nodejs.org/en/feed/vulnerability.xml" },
  { name: "Kubernetes CVE feed", tier: "vendor", url: "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/feed.xml", kind: "cve" },
  { name: "Industrial Cyber", tier: "news", url: "https://industrialcyber.co/feed/" },
  { name: "Utility Dive", tier: "news", url: "https://www.utilitydive.com/feeds/news/", filter: true },
  { name: "Light Reading", tier: "news", url: "https://www.lightreading.com/rss.xml", filter: true },
  { name: "TechCentral (South Africa)", tier: "news", url: "https://techcentral.co.za/feed/", filter: true, region: "africa" },
  { name: "CIO Africa", tier: "news", url: "https://cioafrica.co/feed/", filter: true, region: "africa" },
  { name: "Techzim (Zimbabwe)", tier: "news", url: "https://www.techzim.co.zw/feed/", filter: true, region: "africa" },
  { name: "Hespress (Morocco)", tier: "news", url: "https://fr.hespress.com/feed", filter: true, lang: "fr", region: "africa" },
  { name: "The National (UAE)", tier: "news", url: "https://www.thenationalnews.com/arc/outboundfeeds/rss/?outputType=xml", filter: true, region: "middle-east" },
  { name: "Arab News", tier: "news", url: "https://www.arabnews.com/rss.xml", filter: true, region: "middle-east" },
  { name: "Security Middle East", tier: "news", url: "https://www.securitymiddleeastmag.com/feed/", filter: true, region: "middle-east" },
  { name: "ShiftDelete (Turkey)", tier: "news", url: "https://shiftdelete.net/feed", filter: true, lang: "tr", region: "middle-east" },
  { name: "Ciberseguridad LATAM", tier: "news", url: "https://ciberseguridadlatam.com/feed/", lang: "es", region: "latin-america" },
  { name: "DPL News", tier: "news", url: "https://dplnews.com/feed/", filter: true, lang: "es", region: "latin-america" },
  { name: "El Tiempo tecnosfera (Colombia)", tier: "news", url: "https://www.eltiempo.com/rss/tecnosfera.xml", filter: true, lang: "es", region: "latin-america" },
  { name: "El Financiero (Mexico)", tier: "news", url: "https://www.elfinanciero.com.mx/arc/outboundfeeds/rss/?outputType=xml", filter: true, lang: "es", region: "latin-america" },
  { name: "Convergencia Digital (Brazil)", tier: "news", url: "https://www.convergenciadigital.com.br/feed/", filter: true, lang: "pt", region: "latin-america" },
  { name: "Tecmundo (Brazil)", tier: "news", url: "https://rss.tecmundo.com.br/feed", filter: true, lang: "pt", region: "latin-america" },
  { name: "CNA Singapore", tier: "news", url: "https://www.channelnewsasia.com/api/v1/rss-outbound-feed?_format=xml&category=10416", filter: true, region: "southeast-asia" },
  { name: "Bangkok Post", tier: "news", url: "https://www.bangkokpost.com/rss/data/topstories.xml", filter: true, region: "southeast-asia" },
  { name: "Dailysecu (Korea)", tier: "news", url: "https://www.dailysecu.com/rss/allArticle.xml", filter: true, lang: "ko", region: "east-asia" },
  { name: "Security.nl", tier: "news", url: "https://www.security.nl/rss/headlines.xml", lang: "nl", region: "europe" },
  { name: "ZATAZ", tier: "news", url: "https://www.zataz.com/feed/", lang: "fr", region: "europe" },
  { name: "Sekurak", tier: "news", url: "https://sekurak.pl/feed/", lang: "pl", region: "europe" },
  // fifth batch (2026-11-20): regional research for Africa, the Middle East and Central Asia, Latin America, Asia, and
  // infrastructure and product security. Each was fetched again before it was added: robots.txt allows the feed path for
  // every reader and for ClaudeBot, items are dated with some in the last 30 days, and links stay on the publisher's own sites.
  // Africa
  { name: "ANCS Tunisia", tier: "gov", url: "https://www.ancs.tn/fr/rss.xml", lang: "fr", region: "africa" },
  { name: "NITDA (Nigeria)", tier: "gov", url: "https://nitda.gov.ng/feed/", filter: true, region: "africa" },
  { name: "Eskom media statements", tier: "gov", url: "https://www.eskom.co.za/feed/", filter: true, region: "africa" },
  { name: "TechAfrica News", tier: "news", url: "https://techafricanews.com/feed/", filter: true, region: "africa" },
  { name: "Digital Business Africa", tier: "news", url: "https://www.digitalbusiness.africa/feed/", filter: true, lang: "fr", region: "africa" },
  { name: "Socialnetlink (Senegal)", tier: "news", url: "https://www.socialnetlink.org/feed/", filter: true, lang: "fr", region: "africa" },
  { name: "Daily Maverick (South Africa)", tier: "news", url: "https://www.dailymaverick.co.za/dmrss/", filter: true, region: "africa" },
  { name: "Capital FM (Kenya)", tier: "news", url: "https://capitalfm.africa/news/feed/", filter: true, region: "africa" },
  { name: "Nile Post (Uganda)", tier: "news", url: "https://nilepost.co.ug/feed", filter: true, region: "africa" },
  { name: "Defimedia (Mauritius)", tier: "news", url: "https://defimedia.info/rss.xml", filter: true, lang: "fr", region: "africa" },
  { name: "Menos Fios (Angola)", tier: "news", url: "https://www.menosfios.com/feed/", filter: true, lang: "pt", region: "africa" },
  { name: "TSA Algerie", tier: "news", url: "https://www.tsa-algerie.com/feed/", filter: true, lang: "fr", region: "africa" },
  { name: "TelQuel (Morocco)", tier: "news", url: "https://telquel.ma/feed", filter: true, lang: "fr", region: "africa" },
  { name: "Egypt Independent", tier: "news", url: "https://www.egyptindependent.com/feed/", filter: true, region: "africa" },
  { name: "Al-Masry Al-Youm (Egypt)", tier: "news", url: "https://www.almasryalyoum.com/rss/rssfeeds", filter: true, lang: "ar", region: "africa" },
  // the Middle East, Turkey, Iran, the Caucasus, Central Asia and Pakistan
  { name: "UzCERT (Uzbekistan)", tier: "gov", url: "https://uzcert.uz/feed/", lang: "uz", region: "middle-east" },
  { name: "Teknoblog siber guvenlik (Turkey)", tier: "news", url: "https://www.teknoblog.com/konu/siber-guvenlik/feed/", lang: "tr", region: "middle-east" },
  { name: "Iran International (Persian)", tier: "news", url: "https://www.iranintl.com/fa/feed", filter: true, lang: "fa", region: "middle-east" },
  { name: "Asharq Al-Awsat (Arabic)", tier: "news", url: "https://aawsat.com/feed", filter: true, lang: "ar", region: "middle-east" },
  { name: "Walla Tech (Israel)", tier: "news", url: "https://rss.walla.co.il/feed/4", filter: true, lang: "he", region: "middle-east" },
  { name: "Geektime (Israel)", tier: "news", url: "https://www.geektime.co.il/feed/", filter: true, lang: "he", region: "middle-east" },
  { name: "Globes (Israel)", tier: "news", url: "https://en.globes.co.il/WebService/Rss/RssFeeder.asmx/FeederNode?iID=1725", filter: true, region: "middle-east" },
  { name: "Haberturk teknoloji (Turkey)", tier: "news", url: "https://www.haberturk.com/rss/teknoloji.xml", filter: true, lang: "tr", region: "middle-east" },
  { name: "DonanimHaber (Turkey)", tier: "news", url: "https://www.donanimhaber.com/rss/tum/", filter: true, lang: "tr", region: "middle-east" },
  { name: "ProPakistani", tier: "news", url: "https://propakistani.pk/feed/", filter: true, region: "south-asia" },
  { name: "Express Tribune technology (Pakistan)", tier: "news", url: "https://tribune.com.pk/feed/technology", filter: true, region: "south-asia" },
  // Latin America and the Caribbean
  { name: "CERT-PY (Paraguay)", tier: "gov", url: "https://www.cert.gov.py/feed/", lang: "es", region: "latin-america" },
  { name: "CNCS (Dominican Republic)", tier: "gov", url: "https://cncs.gob.do/feed/", filter: true, lang: "es", region: "latin-america" },
  { name: "G1 tecnologia (Brazil)", tier: "news", url: "https://g1.globo.com/rss/g1/tecnologia/", filter: true, lang: "pt", region: "latin-america" },
  { name: "Tele.Sintese (Brazil)", tier: "news", url: "https://telesintese.com.br/feed/", filter: true, lang: "pt", region: "latin-america" },
  { name: "Expansion tecnologia (Mexico)", tier: "news", url: "https://expansion.mx/rss/tecnologia", filter: true, lang: "es", region: "latin-america" },
  { name: "La Nacion tecnologia (Argentina)", tier: "news", url: "https://www.lanacion.com.ar/arc/outboundfeeds/rss/category/tecnologia/?outputType=xml", filter: true, lang: "es", region: "latin-america" },
  { name: "Ambito tecnologia (Argentina)", tier: "news", url: "https://www.ambito.com/rss/pages/tecnologia.xml", filter: true, lang: "es", region: "latin-america" },
  { name: "iProfesional tecnologia (Argentina)", tier: "news", url: "https://www.iprofesional.com/rss/tecnologia", filter: true, lang: "es", region: "latin-america" },
  { name: "Semana tecnologia (Colombia)", tier: "news", url: "https://www.semana.com/arc/outboundfeeds/rss/category/tecnologia/?outputType=xml", filter: true, lang: "es", region: "latin-america" },
  { name: "El Comercio tecnologia (Peru)", tier: "news", url: "https://elcomercio.pe/arc/outboundfeeds/rss/category/tecnologia/?outputType=xml", filter: true, lang: "es", region: "latin-america" },
  { name: "ABC Color tecnologia (Paraguay)", tier: "news", url: "https://www.abc.com.py/arc/outboundfeeds/rss/category/tecnologia/?outputType=xml", filter: true, lang: "es", region: "latin-america" },
  { name: "Diario Financiero (Chile)", tier: "news", url: "https://www.df.cl/noticias/site/list/port/rss.xml", filter: true, lang: "es", region: "latin-america" },
  // Asia and Oceania
  { name: "GovCERT.HK security alerts", tier: "gov", url: "https://www.govcert.gov.hk/en/rss_security_alerts.xml", region: "east-asia" },
  { name: "Digital Agency Japan", tier: "gov", url: "https://www.digital.go.jp/rss/news.xml", filter: true, lang: "ja", region: "east-asia" },
  { name: "LAC Watch (Japan)", tier: "vendor", url: "https://www.lac.co.jp/lacwatch/feed.xml", filter: true, lang: "ja", region: "east-asia" },
  { name: "piyolog (Japan)", tier: "news", url: "https://piyolog.hatenadiary.jp/rss", lang: "ja", region: "east-asia" },
  { name: "ScanNetSecurity (Japan)", tier: "news", url: "https://scan.netsecurity.ne.jp/rss/index.rdf", lang: "ja", region: "east-asia" },
  { name: "Mynavi TECH+ security (Japan)", tier: "news", url: "https://news.mynavi.jp/rss/techplus/enterprise/security", lang: "ja", region: "east-asia" },
  { name: "Cybersecurity.com (Japan)", tier: "news", url: "https://cybersecurity-jp.com/feed", lang: "ja", region: "east-asia" },
  { name: "INTERNET Watch (Japan)", tier: "news", url: "https://internet.watch.impress.co.jp/data/rss/1.0/iw/feed.rdf", filter: true, lang: "ja", region: "east-asia" },
  { name: "Etnews security (Korea)", tier: "news", url: "https://rss.etnews.com/04045.xml", lang: "ko", region: "east-asia" },
  { name: "SCMP technology (Hong Kong)", tier: "news", url: "https://www.scmp.com/rss/36/feed/", filter: true, region: "east-asia" },
  { name: "VnExpress khoa hoc cong nghe (Vietnam)", tier: "news", url: "https://vnexpress.net/rss/khoa-hoc-cong-nghe.rss", filter: true, lang: "vi", region: "southeast-asia" },
  { name: "Tuoi Tre nhip song so (Vietnam)", tier: "news", url: "https://tuoitre.vn/rss/nhip-song-so.rss", filter: true, lang: "vi", region: "southeast-asia" },
  { name: "CNN Indonesia teknologi", tier: "news", url: "https://www.cnnindonesia.com/teknologi/rss", filter: true, lang: "id", region: "southeast-asia" },
  { name: "Inquirer technology (Philippines)", tier: "news", url: "https://technology.inquirer.net/feed", filter: true, region: "southeast-asia" },
  { name: "Blognone (Thailand)", tier: "news", url: "https://www.blognone.com/atom.xml", filter: true, lang: "th", region: "southeast-asia" },
  { name: "Amar Ujala technology (India)", tier: "news", url: "https://www.amarujala.com/rss/technology.xml", filter: true, lang: "hi", region: "south-asia" },
  { name: "Information Age (Australia)", tier: "news", url: "https://ia.acs.org.au/articles.rss", filter: true, region: "oceania" },
  // Europe: national agencies not yet covered
  { name: "NKI Hungary alerts", tier: "gov", url: "https://nki.gov.hu/feed/riasztasok/", lang: "hu", region: "europe" },
  { name: "NKI Hungary news", tier: "gov", url: "https://nki.gov.hu/feed/hirek/", filter: true, lang: "hu", region: "europe" },
  { name: "Styrelsen for Samfundssikkerhed (Denmark)", tier: "gov", url: "https://samsik.dk/feed/", filter: true, lang: "da", region: "europe" },
  { name: "GovCERT Bulgaria", tier: "gov", url: "https://www.govcert.bg/feed/", lang: "bg", region: "europe" },
  { name: "CERT.hr (Croatia)", tier: "gov", url: "https://cert.hr/feed/", lang: "hr", region: "europe" },
  { name: "SI-CERT (Slovenia)", tier: "gov", url: "https://www.cert.si/feed/", lang: "sl", region: "europe" },
  { name: "RIA (Estonia)", tier: "gov", url: "https://www.ria.ee/rss-feeds/rss.xml", filter: true, lang: "et", region: "europe" },
  { name: "CERT@VDE", tier: "gov", url: "https://certvde.com/en/advisories/feeds/rss/", kind: "cve", region: "europe" },
  // infrastructure and product security teams
  { name: "Ivanti security advisories", tier: "vendor", url: "https://www.ivanti.com/blog/topics/security-advisory/rss" },
  { name: "Synology security advisories", tier: "vendor", url: "https://www.synology.com/api/rssfeed/security/en-global", kind: "cve" },
  { name: "Moxa security advisories", tier: "vendor", url: "https://www.moxa.com/en/rss/moxa-security-advisory", kind: "cve" },
  { name: "SolarWinds security advisories", tier: "vendor", url: "https://www.solarwinds.com/shared-content/rss-feed/solarwinds-cve-rss-feed.xml", kind: "cve" },
  { name: "ABB PSIRT", tier: "vendor", url: "https://psirt.abb.com/rss/abbrssfeed.xml", kind: "cve" },
  { name: "F5 Labs", tier: "vendor", url: "https://www.f5.com/labs/rss-feeds/all.xml" },
  { name: "VulnCheck", tier: "vendor", url: "https://www.vulncheck.com/feed/blog/atom.xml" },
  { name: "Censys", tier: "vendor", url: "https://censys.com/feed/", filter: true },
  { name: "Bishop Fox", tier: "vendor", url: "https://bishopfox.com/feeds/blog.rss", filter: true },
  { name: "Healthcare Dive health IT", tier: "news", url: "https://www.healthcaredive.com/feeds/topic/health-it/", filter: true },
  { name: "RCR Wireless News", tier: "news", url: "https://rcrwireless.com/feed", filter: true },
];
// Extra feeds come from config/feeds.json (the source scout's hand-kept list, with its retired and watch lists) and from the
// shards in config/feeds.d/*.json (the bulk source lists, one file per region or sector, each {_note, first_run_hours?, feeds}).
// Every entry is checked by scripts/feed-check.mjs before it is added (robots.txt, parses, recent items, publisher's own links).
export const MAX_EXTRA = 5000;
/** The merged feed config: config/feeds.json plus every shard in config/feeds.d. A broken shard is skipped, never fatal.
 *  A shard's first_run_hours is copied onto each of its feeds (bulk additions file little on their first run). */
export function loadFeedConfig(root = ROOT) {
  const cfg = readJson(join(root, "config", "feeds.json"), {}) || {}, feeds = Array.isArray(cfg.feeds) ? cfg.feeds.slice() : [];
  const dir = join(root, "config", "feeds.d");
  if (existsSync(dir)) for (const f of readdirSync(dir).filter((f) => f.endsWith(".json")).sort()) {
    const sh = readJson(join(dir, f), null);
    if (!sh || !Array.isArray(sh.feeds)) continue;
    const frh = Number.isFinite(sh.first_run_hours) ? sh.first_run_hours : null;
    for (const x of sh.feeds) if (x && typeof x === "object") feeds.push({ ...(frh != null && x.first_run_hours == null ? { first_run_hours: frh } : {}), ...x, shard: f.slice(0, -5) });
  }
  return { ...cfg, feeds };
}
/** Pure: the same feed under www., http/https or a trailing slash is still the same feed. */
export const feedKey = (u) => { try { const x = new URL(u); return `${x.hostname.replace(/^www\./, "").toLowerCase()}${x.pathname.replace(/\/+$/, "")}${x.search}`; } catch { return String(u); } };
// feeds the source scout job and the shards have added; a broken entry is ignored, never fatal
export function extraFeeds(cfg) {
  const names = new Set(FEEDS.map((f) => f.name.toLowerCase())), urls = new Set(FEEDS.map((f) => feedKey(f.url)));
  return (cfg && Array.isArray(cfg.feeds) ? cfg.feeds : []).filter((f) => f && typeof f.name === "string" && f.name.length <= 80 && ["gov", "vendor", "news"].includes(f.tier)
    && /^https:\/\/[^\s"'<>]+$/.test(f.url || "") && !names.has(f.name.toLowerCase()) && !urls.has(feedKey(f.url)) && names.add(f.name.toLowerCase()) && urls.add(feedKey(f.url))).slice(0, MAX_EXTRA);
}
/** Every feed to collect: the built-in list and the extra feeds, minus any name the config retires (so the source scout can
 *  retire a built-in feed that died or now refuses automated readers without a code change). */
export function activeFeeds(cfg) {
  const retired = new Set((cfg && Array.isArray(cfg.retired) ? cfg.retired : []).map((r) => String((r && r.name) || "").toLowerCase()).filter(Boolean));
  return FEEDS.concat(extraFeeds(cfg)).filter((f) => !retired.has(f.name.toLowerCase()));
}

// How often a feed is asked (2026-11-24, when the list grew from 280 to ~2,500 feeds): government and CERT feeds every
// 10 minutes, vendors every 15, news every 20; a feed may set every_minutes. A feed that has filed no lead for 3 days is
// asked three times less often (its next lead is found a little later, never lost: items stay in the 72-hour window).
export const EVERY_MIN = { gov: 10, vendor: 15, news: 20 }, QUIET_DAYS = 3, QUIET_FACTOR = 3;
/** Pure: minutes between asks for feed f with health h. */
export function intervalMin(f, h, now = Date.now()) {
  const base = Number(f.every_minutes) > 0 ? Number(f.every_minutes) : EVERY_MIN[f.tier] || 20;
  const lastLead = Date.parse((h && (h.last_lead_at || h.first_ok)) || "");
  return isFinite(lastLead) && now - lastLead > QUIET_DAYS * 864e5 ? base * QUIET_FACTOR : base;
}
/** Pure: the feeds to ask this run, most overdue first: never asked, then by how far past their interval they are.
 *  A failing feed waits for its backoff (due()). */
export function pickDue(all, health, now = Date.now()) {
  const scored = [];
  for (const f of all) {
    const h = health[f.name];
    if (!due(h, now)) continue;
    const at = Date.parse((h && h.at) || "");
    if (!isFinite(at)) { scored.push([Infinity, f]); continue; }
    const over = (now - at) / 6e4 - intervalMin(f, h, now);
    if (over >= 0) scored.push([over, f]);
  }
  return scored.sort((a, b) => b[0] - a[0]).map((x) => x[1]);
}
/** Run fetches host by host: up to `width` hosts at once, one request at a time to any one host, and nothing new started
 *  after `deadline` (ms epoch). Returns [{f, ...result}] for the feeds asked; the rest wait for the next run. */
export async function runPolite(feeds, fetchOne, { width = 32, deadline = Infinity } = {}) {
  const byHost = new Map();
  for (const f of feeds) { let h; try { h = new URL(f.url).hostname; } catch { h = f.url; } if (!byHost.has(h)) byHost.set(h, []); byHost.get(h).push(f); }
  const hosts = [...byHost.values()], out = [];
  let next = 0;
  const worker = async () => {
    while (next < hosts.length) {
      const q = hosts[next++];
      for (const f of q) { if (Date.now() >= deadline) return; out.push({ f, ...(await fetchOne(f)) }); }
    }
  };
  await Promise.all(Array.from({ length: Math.min(width, hosts.length) }, worker));
  return out;
}

// cyber words in the languages the broad feeds are written in (a filter that knew only English kept nothing from El Pais)
export const CYBER = new RegExp(["cyber|hack(?!athon)|ransom|breach|malware|botnet|phish|dark ?web|ddos|vulnerab|exploit|intrusion|data theft|stolen data|spyware|crypto(currency)? (fraud|theft|scam)|sim[- ]swap|extort|computer fraud|identity theft",
  "ciberataque|ciberseguridad|cibern[eé]tic|ciberdelincuen|cibercrim|hackeo|filtraci[oó]n de datos|secuestro de datos|vazamento de dados|sequestro de dados|ataque hacker|invas[aã]o hacker",   // es, pt
  "piratage|ran[cç]ongiciel|fuite de donn[ée]es|attacco informatico|violazione dei dati|datenleck|sicherheitsl[uü]cke|schadsoftware|datalek|wyciek danych",   // fr, it, de, nl, pl
  "\\bsiber\\b|fidye yaz[ıi]l[ıi]m|veri s[ıi]z[ıi]nt[ıi]s[ıi]|veri ihlal|g[üu]venlik a[çc][ıi][ğg][ıi]|kimlik av[ıi]|zararl[ıi] yaz[ıi]l[ıi]m|peretas|kebocoran data|diretas|tin tặc|mã độc|rò rỉ dữ liệu",   // tr, id/ms, vi
  "سيبراني|اختراق|قرصنة|الفدية|تسريب بيانات|هجوم [إا]لكترون[يى]|هجمات [إا]لكترونية|برمجيات خبيثة|кибер|хакер|взлом|утечк|вымогател",   // ar, ru/uk
  "サイバー|不正アクセス|情報漏え?い|漏洩|ランサム|脆弱性|マルウェア|해킹|랜섬웨어|유출|취약점|사이버|악성코드|피싱|漏洞|駭客|黑客|勒索|資安|網路攻擊|网络攻击|外洩|泄露|ไซเบอร์|แฮ็ก|มัลแวร์|ช่องโหว่",   // ja, ko, zh, th
  // only words that mean nothing but an IT attack or leak: generic "vulnerability" words (sårbarhed, ranjivost, sebezhetőség) also
  // describe people, so they are left out; "kiber" is not Kibera (Nairobi)
  "\\bkiber(?!a\\b)|k[üu]ber(?!net)|adatsziv[aá]rg|zsarol[oó]v[ií]rus|s[ée]r[üu]l[ée]kenys[ée]g|adathal[aá]sz|k[aá]rt[ée]kony k[oó]d|datal[æa]k|it-angreb|turvan[õo]rkus|andmelek|lunavara|pahavara|[õo]ngitsus",   // hu, uz, hr, sl, da, et
  // sw, ha, am, af (regional coverage, 2026-11-21): Swahili "-dukua" (to hack: wadukuzi, imedukuliwa; not "dukuduku", curiosity)
  // and attacks or crime "of the network"; Hausa attack on the internet, intruders ("masu kutse") and data theft; Amharic
  // "cyber"; Afrikaans ransomware ("losprys"), with "kuber" already read above (and Kubernetes no longer mistaken for it)
  "dukuzi|dukua|dukuliwa|(mashambulizi|mashambulio|shambulio|uhalifu|usalama) (ya|la|wa) (ki)?mtandao|har(in|e-haren) (intanet|yanar gizo)|masu kutse|satar bayanai|tsaron yanar gizo|ሳይበር|losprys",
  "سایبر|هکر|باج\u200c?افزار|بدافزار|نشت اطلاعات|فیشینگ|סייבר|האקר|כופרה|נוזקה|דליפת מידע|חולשת אבטחה|פישינג|साइबर|हैकर|हैकिंग|रैनसमवेयर|मालवेयर|डेटा लीक|फिशिंग"].join("|"), "i");   // fa, he, hi
const MAX_AGE_H = 72;
// a feed seen for the first time (no last_ok in osint.json) files only its last day: adding many feeds at once would
// otherwise file up to three days of each one's items in a single run and flood the research queue
export const FIRST_RUN_H = 24;
/** Pure: is this text about cyber security? "exploit" alone means a feat in French, Spanish, Portuguese and Italian
 *  (a football "exploit"), so outside English it needs another cyber word next to it. */
export function isCyber(text, lang = "en") {
  const t = String(text || "");
  if (!CYBER.test(t)) return false;
  if (!/^(fr|es|pt|it)/.test(lang || "en")) return true;
  const re = new RegExp(CYBER.source, CYBER.flags.includes("g") ? CYBER.flags : CYBER.flags + "g");
  return [...t.matchAll(re)].some((m) => !/^exploit/i.test(m[0]));
}

const decode = (s) => String(s || "").replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(+n)).replace(/&amp;/g, "&");
const text = (s, n) => decode(s).replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const tag = (block, names) => { for (const t of names) { const m = block.match(new RegExp(`<${t}\\b[^>]*>([\\s\\S]*?)</${t}>`, "i")); if (m) return m[1]; } return ""; };
const atomLink = (block) => { const m = block.match(/<link\b[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["']/i) || block.match(/<link\b[^>]*href=["']([^"']+)["']/i); return m ? decode(m[1]) : ""; };

export function parseFeed(xml) {
  const items = [];
  for (const m of xml.matchAll(/<(item|entry)\b[\s\S]*?<\/\1>/gi)) {
    const b = m[0];
    const title = text(tag(b, ["title"]), 200);
    // long enough for a Bing redirect around a percent-encoded non-Latin article address (a cut one is a broken link)
    let url = text(tag(b, ["link"]), 4000);
    if (!/^https?:\/\//.test(url)) url = atomLink(b);
    const dateRaw = text(tag(b, ["pubDate", "published", "updated", "dc:date"]), 60);
    const t = Date.parse(dateRaw);
    const summary = text(tag(b, ["description", "summary", "content"]), 300);
    if (title && /^https?:\/\//.test(url)) items.push({ title, url: url.trim(), published: isNaN(t) ? "" : new Date(t).toISOString().replace(/\.\d+Z$/, "Z"), summary });
  }
  return items;
}

export const MAX_BYTES = 5e6;
/** Fetch one feed. cond: {etag, lastmod} from the last good fetch; a 304 answer is {items: [], notModified: true}. */
// health fields that outlive one fetch (conditional-GET validators, first success, last lead)
const keep = (p) => Object.fromEntries(["etag", "lastmod", "first_ok", "last_lead_at"].filter((k) => p[k]).map((k) => [k, p[k]]));
export async function fetchFeed(f, cond = {}) {
  for (let i = 0; i < 2; i++) {
    try {
      // A feed reader's Accept prefers the feed types but ends in */* (#135), so a server that content-negotiates still
      // returns the feed; if it still answers 415, ask once more at once without an accept list (#136), same identifying
      // user-agent. Not the 5 s retry below, and a 415 that persists still fails as a 415. A conditional GET (ETag,
      // Last-Modified) lets an unchanged feed answer 304 with no body: with ~2,500 feeds, most asks are unchanged.
      const condH = { ...(cond.etag ? { "if-none-match": cond.etag } : {}), ...(cond.lastmod ? { "if-modified-since": cond.lastmod } : {}) };
      const ask = (accept) => fetch(f.url, { headers: { "user-agent": "cyberview-collector/1.0 (+https://github.com/xanderhutch/CyberView)", ...condH, ...(accept ? { accept } : {}) }, signal: AbortSignal.timeout(20000) });
      let r = await ask("application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.8");
      if (r.status === 415) r = await ask("");
      if (r.status === 304) return { items: [], notModified: true };
      if (r.status === 403 || r.status === 401) return { error: `HTTP ${r.status} (refuses automated readers; not retried)` };
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const hd = (k) => (r.headers && typeof r.headers.get === "function" ? r.headers.get(k) || "" : "");
      if (Number(hd("content-length")) > MAX_BYTES) return { error: "feed larger than 5 MB" };
      const body = await r.text();
      return { items: parseFeed(body.length > MAX_BYTES ? body.slice(0, MAX_BYTES) : body), etag: hd("etag").slice(0, 200), lastmod: hd("last-modified").slice(0, 60) };
    } catch (e) { if (i === 1) return { error: (e.cause && e.cause.code) || e.message }; await new Promise((res) => setTimeout(res, 5000)); }
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  // --test <url>: the source scout checks a candidate feed before adding it (reads and writes nothing)
  // --test (no url): a dry run of the whole collection: every feed is fetched and filtered as usual, nothing is written
  const ti = process.argv.indexOf("--test"), turl = ti > 0 ? process.argv[ti + 1] || "" : "";
  if (/^https?:\/\//.test(turl)) { const r = await fetchFeed({ url: turl }); console.log(r.error ? `FAILED: ${r.error}` : `OK: ${r.items.length} items; newest: ${JSON.stringify(r.items.slice(0, 3).map((i) => [i.published.slice(0, 10), i.title.slice(0, 80)]))}`); process.exit(r.error || !r.items.length ? 1 : 0); }
  const DRY = ti > 0;
  const leadsDir = join(DATA, "leads");
  if (!DRY) mkdirSync(leadsDir, { recursive: true });
  const known = new Set();
  for (const x of listEventFiles()) for (const s of (x.e && x.e.sources) || []) if (s && s.url) known.add(s.url);
  for (const f of existsSync(leadsDir) ? readdirSync(leadsDir) : []) {
    if (!f.endsWith(".jsonl") || f.slice(0, 10) < dayAgo(14)) continue;
    for (const line of readFileSync(join(leadsDir, f), "utf8").split("\n")) { try { known.add(JSON.parse(line).url); } catch {} }
  }
  const cutoff = Date.now() - MAX_AGE_H * 36e5, now = nowIso(), out = [], report = [];
  const ALL = activeFeeds(loadFeedConfig());
  const hp = join(DATA, "osint.json"), hdoc = readJson(hp, {}), fh = hdoc.feeds || {};
  // each feed is asked on its own interval (intervalMin), most overdue first, host by host, within the run's time budget
  // (COLLECT_BUDGET_S, default 180 s, so the research loop's cycle and the workflow step keep their pace): what is not
  // reached is first in line next run. A failing feed waits for its backoff (scripts/lib/backoff.mjs).
  const budgetS = Number(process.env.COLLECT_BUDGET_S) || 180;
  const asked = DRY ? ALL : pickDue(ALL, fh);
  const failing = ALL.filter((f) => !due(fh[f.name]));
  for (const f of failing) report.push(`${f.name}: failing, not asked until ${fh[f.name].next_try_at} (${fh[f.name].fails} runs: ${fh[f.name].error})`);
  const results = await runPolite(asked, (f) => fetchFeed(f, DRY ? {} : { etag: (fh[f.name] || {}).etag, lastmod: (fh[f.name] || {}).lastmod }),
    { width: Number(process.env.COLLECT_WIDTH) || 32, deadline: DRY ? Infinity : Date.now() + budgetS * 1000 });
  for (const { f, items, error, notModified, etag, lastmod } of results) {
    const prev = fh[f.name] || {};
    // per-feed health: consecutive failures are counted (and backed off) so the source scout can repair or retire a dead feed
    if (error) { fh[f.name] = nextHealth(prev, { ok: false, error, extra: keep(prev) }); report.push(`${f.name}: ${error}`); continue; }
    let n = 0, recent = 0;
    const firstH = Number.isFinite(f.first_run_hours) ? f.first_run_hours : FIRST_RUN_H;
    const since = prev.last_ok ? cutoff : Math.max(cutoff, Date.now() - firstH * 36e5);
    for (const it of items) {
      if (known.has(it.url)) continue;
      if (it.published && Date.parse(it.published) < since) continue;
      recent++;
      if (f.filter && !isCyber(`${it.title} ${it.summary}`, f.lang)) continue;
      known.add(it.url); n++;
      out.push({ seen_at: now, source: f.name, tier: f.tier, via: "rss", title: it.title, url: it.url, published: it.published, summary: it.summary, lang: f.lang || "en", ...(f.region ? { region: f.region } : {}), ...(f.kind ? { kind: f.kind } : {}) });
    }
    const extra = { ...keep(prev), ...(notModified ? {} : { etag: etag || "", lastmod: lastmod || "" }), first_ok: prev.first_ok || prev.last_ok || now,
      ...(n ? { last_lead_at: now } : {}), ...(items.length || notModified ? {} : { empty: (prev.empty || 0) + 1 }) };
    fh[f.name] = nextHealth(prev, { ok: true, items: notModified ? prev.items || 0 : items.length, extra });
    report.push(`${f.name}: ${notModified ? "not modified" : `${items.length} in feed, ${n} new${f.filter ? ` (${n} of ${recent} recent passed the cyber filter)` : ""}`}`);
  }
  report.push(`asked ${results.length} of ${asked.length} due (of ${ALL.length} feeds); ${asked.length - results.length} left for the next run`);
  if (DRY) { console.log(`collect --test (dry run, nothing written): ${out.length} new lead(s) from ${ALL.length} feeds.\n` + report.join("\n")); process.exit(0); }
  if (out.length) appendFileSync(join(leadsDir, `${now.slice(0, 10)}.jsonl`), out.map((x) => JSON.stringify(x)).join("\n") + "\n");
  const sp = join(DATA, "status.json"), st = readStatus();
  st.last_collect_at = now; st.last_collect_new = out.length;
  writeJson(sp, st);
  const names = new Set(ALL.map((f) => f.name));
  for (const k of Object.keys(fh)) if (!names.has(k)) delete fh[k];
  writeJson(hp, { ...hdoc, feeds: fh, feeds_checked_at: now });
  st.collect_feeds = ALL.length; st.collect_feeds_ok = Object.values(fh).filter((v) => v.ok).length;
  // one bad run is noise: only feeds that failed three runs in a row are reported as not loading
  st.collect_failed = Object.entries(fh).filter(([, v]) => !v.ok && v.fails >= 3).map(([k, v]) => `${k}: ${v.error} (${v.fails} runs)`);
  writeJson(sp, st);
  console.log(`collect: ${out.length} new lead(s) from ${ALL.length} feeds.\n` + report.join("\n"));
}

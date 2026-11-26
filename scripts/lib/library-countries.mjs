// A fixed list of countries for the Library's story checks (scripts/lib/library-check.mjs): every UN member state plus common short forms
// and a few places often named in threat reports (Taiwan, Hong Kong, Kosovo, Palestine), with demonyms for the most commonly named ones.
// A story sentence that names a country here must have a cited card (or the catalogue record, when cited) that names it too. Pure data.
//
// Each entry: [canonical, ...other names and demonyms]. Names are matched case-sensitively as whole words (see countriesIn), so "turkey"
// the bird and "polish" the verb are not countries. AMBIGUOUS names are ordinary words or US states as well; they count only in a sentence
// that also has a state word (sponsored, government, military, intelligence ...).
export const COUNTRIES = [
  ["Afghanistan", "Afghan"], ["Albania", "Albanian"], ["Algeria", "Algerian"], ["Andorra"], ["Angola", "Angolan"], ["Antigua and Barbuda"],
  ["Argentina", "Argentine", "Argentinian"], ["Armenia", "Armenian"], ["Australia", "Australian"], ["Austria", "Austrian"], ["Azerbaijan", "Azerbaijani"],
  ["Bahamas"], ["Bahrain", "Bahraini"], ["Bangladesh", "Bangladeshi"], ["Barbados"], ["Belarus", "Belarusian"], ["Belgium", "Belgian"], ["Belize"],
  ["Benin"], ["Bhutan"], ["Bolivia", "Bolivian"], ["Bosnia and Herzegovina", "Bosnia", "Bosnian"], ["Botswana"], ["Brazil", "Brazilian"],
  ["Brunei"], ["Bulgaria", "Bulgarian"], ["Burkina Faso"], ["Burundi"], ["Cabo Verde", "Cape Verde"], ["Cambodia", "Cambodian"], ["Cameroon", "Cameroonian"],
  ["Canada", "Canadian"], ["Central African Republic"], ["Chad", "Chadian"], ["Chile", "Chilean"], ["China", "Chinese", "PRC", "People's Republic of China"],
  ["Colombia", "Colombian"], ["Comoros"], ["Congo", "Congolese", "DRC", "Democratic Republic of the Congo"], ["Costa Rica"], ["Côte d'Ivoire", "Ivory Coast"],
  ["Croatia", "Croatian"], ["Cuba", "Cuban"], ["Cyprus", "Cypriot"], ["Czechia", "Czech Republic", "Czech"], ["Denmark", "Danish"], ["Djibouti"],
  ["Dominica"], ["Dominican Republic", "Dominican"], ["Ecuador", "Ecuadorian"], ["Egypt", "Egyptian"], ["El Salvador"], ["Equatorial Guinea"], ["Eritrea", "Eritrean"],
  ["Estonia", "Estonian"], ["Eswatini", "Swaziland"], ["Ethiopia", "Ethiopian"], ["Fiji"], ["Finland", "Finnish"], ["France", "French"], ["Gabon"],
  ["Gambia"], ["Georgia", "Georgian"], ["Germany", "German"], ["Ghana", "Ghanaian"], ["Greece", "Greek"], ["Grenada"], ["Guatemala", "Guatemalan"],
  ["Guinea"], ["Guinea-Bissau"], ["Guyana"], ["Haiti", "Haitian"], ["Honduras"], ["Hungary", "Hungarian"], ["Iceland", "Icelandic"], ["India", "Indian"],
  ["Indonesia", "Indonesian"], ["Iran", "Iranian"], ["Iraq", "Iraqi"], ["Ireland", "Irish"], ["Israel", "Israeli"], ["Italy", "Italian"], ["Jamaica", "Jamaican"],
  ["Japan", "Japanese"], ["Jordan", "Jordanian"], ["Kazakhstan", "Kazakh"], ["Kenya", "Kenyan"], ["Kiribati"], ["Kuwait", "Kuwaiti"], ["Kyrgyzstan", "Kyrgyz"],
  ["Laos", "Lao"], ["Latvia", "Latvian"], ["Lebanon", "Lebanese"], ["Lesotho"], ["Liberia", "Liberian"], ["Libya", "Libyan"], ["Liechtenstein"],
  ["Lithuania", "Lithuanian"], ["Luxembourg"], ["Madagascar"], ["Malawi"], ["Malaysia", "Malaysian"], ["Maldives"], ["Mali", "Malian"], ["Malta", "Maltese"],
  ["Marshall Islands"], ["Mauritania"], ["Mauritius"], ["Mexico", "Mexican"], ["Micronesia"], ["Moldova", "Moldovan"], ["Monaco"], ["Mongolia", "Mongolian"],
  ["Montenegro"], ["Morocco", "Moroccan"], ["Mozambique"], ["Myanmar", "Burma", "Burmese"], ["Namibia"], ["Nauru"], ["Nepal", "Nepalese"],
  ["Netherlands", "Dutch", "Holland"], ["New Zealand"], ["Nicaragua"], ["Niger"], ["Nigeria", "Nigerian"], ["North Korea", "North Korean", "DPRK"],
  ["North Macedonia", "Macedonia", "Macedonian"], ["Norway", "Norwegian"], ["Oman", "Omani"], ["Pakistan", "Pakistani"], ["Palau"], ["Panama", "Panamanian"],
  ["Papua New Guinea"], ["Paraguay"], ["Peru", "Peruvian"], ["Philippines", "Filipino", "Philippine"], ["Poland", "Polish"], ["Portugal", "Portuguese"],
  ["Qatar", "Qatari"], ["Romania", "Romanian"], ["Russia", "Russian", "Russian Federation"], ["Rwanda", "Rwandan"], ["Saint Kitts and Nevis"], ["Saint Lucia"],
  ["Saint Vincent and the Grenadines"], ["Samoa"], ["San Marino"], ["São Tomé and Príncipe", "Sao Tome and Principe"], ["Saudi Arabia", "Saudi"],
  ["Senegal", "Senegalese"], ["Serbia", "Serbian"], ["Seychelles"], ["Sierra Leone"], ["Singapore", "Singaporean"], ["Slovakia", "Slovak"],
  ["Slovenia", "Slovenian"], ["Solomon Islands"], ["Somalia", "Somali"], ["South Africa", "South African"], ["South Korea", "South Korean", "ROK", "Republic of Korea"],
  ["South Sudan"], ["Spain", "Spanish"], ["Sri Lanka", "Sri Lankan"], ["Sudan", "Sudanese"], ["Suriname"], ["Sweden", "Swedish"], ["Switzerland", "Swiss"],
  ["Syria", "Syrian"], ["Tajikistan", "Tajik"], ["Tanzania", "Tanzanian"], ["Thailand", "Thai"], ["Timor-Leste", "East Timor"], ["Togo"], ["Tonga"],
  ["Trinidad and Tobago"], ["Tunisia", "Tunisian"], ["Turkey", "Turkish", "Türkiye", "Turkiye"], ["Turkmenistan", "Turkmen"], ["Tuvalu"], ["Uganda", "Ugandan"],
  ["Ukraine", "Ukrainian"], ["United Arab Emirates", "UAE", "Emirati"], ["United Kingdom", "UK", "U.K.", "Britain", "British", "Great Britain"],
  ["United States", "US", "U.S.", "USA", "U.S.A.", "America", "American"], ["Uruguay", "Uruguayan"], ["Uzbekistan", "Uzbek"], ["Vanuatu"],
  ["Venezuela", "Venezuelan"], ["Vietnam", "Viet Nam", "Vietnamese"], ["Yemen", "Yemeni"], ["Zambia", "Zambian"], ["Zimbabwe", "Zimbabwean"],
  // not UN members, often named in threat reporting
  ["Taiwan", "Taiwanese"], ["Hong Kong"], ["Kosovo"], ["Palestine", "Palestinian"], ["Macau", "Macao"],
  // a bare "Korea"/"Korean" is held by a card naming either Korea
  ["Korea", "Korean"],
];
/** Names that are also ordinary words or US states: they count only in a sentence that also carries a state word. */
export const AMBIGUOUS = new Set(["Chad", "Georgia", "Jordan", "Turkey", "Niger", "Guinea", "America", "Holland", "Dominica", "Panama"]);

// US states for the grid source file us.mjs: FIPS code -> postal abbreviation, name and an approximate centre (a rough
// point for a coarse region, used only when a feed's items carry no coordinates; never a location claim).
// Not loaded as a source (files starting with "lib-" are skipped by scripts/grid.mjs).
export const US_STATES = {
  "01": ["AL", "Alabama", 32.8, -86.8], "02": ["AK", "Alaska", 61.4, -150.0], "04": ["AZ", "Arizona", 34.3, -111.7],
  "05": ["AR", "Arkansas", 34.9, -92.4], "06": ["CA", "California", 37.2, -119.5], "08": ["CO", "Colorado", 39.0, -105.5],
  "09": ["CT", "Connecticut", 41.6, -72.7], "10": ["DE", "Delaware", 39.0, -75.5], "11": ["DC", "District of Columbia", 38.9, -77.0],
  "12": ["FL", "Florida", 28.6, -82.4], "13": ["GA", "Georgia", 32.7, -83.4], "15": ["HI", "Hawaii", 20.8, -156.3],
  "16": ["ID", "Idaho", 44.4, -114.6], "17": ["IL", "Illinois", 40.0, -89.2], "18": ["IN", "Indiana", 39.9, -86.3],
  "19": ["IA", "Iowa", 42.1, -93.5], "20": ["KS", "Kansas", 38.5, -98.4], "21": ["KY", "Kentucky", 37.5, -85.3],
  "22": ["LA", "Louisiana", 31.1, -92.0], "23": ["ME", "Maine", 45.4, -69.2], "24": ["MD", "Maryland", 39.0, -76.8],
  "25": ["MA", "Massachusetts", 42.3, -71.8], "26": ["MI", "Michigan", 44.3, -85.4], "27": ["MN", "Minnesota", 46.3, -94.3],
  "28": ["MS", "Mississippi", 32.7, -89.7], "29": ["MO", "Missouri", 38.4, -92.5], "30": ["MT", "Montana", 47.0, -109.6],
  "31": ["NE", "Nebraska", 41.5, -99.8], "32": ["NV", "Nevada", 39.3, -116.6], "33": ["NH", "New Hampshire", 43.7, -71.6],
  "34": ["NJ", "New Jersey", 40.2, -74.7], "35": ["NM", "New Mexico", 34.4, -106.1], "36": ["NY", "New York", 42.9, -75.5],
  "37": ["NC", "North Carolina", 35.6, -79.4], "38": ["ND", "North Dakota", 47.5, -100.5], "39": ["OH", "Ohio", 40.3, -82.8],
  "40": ["OK", "Oklahoma", 35.6, -97.5], "41": ["OR", "Oregon", 43.9, -120.6], "42": ["PA", "Pennsylvania", 40.9, -77.8],
  "44": ["RI", "Rhode Island", 41.7, -71.5], "45": ["SC", "South Carolina", 33.9, -80.9], "46": ["SD", "South Dakota", 44.4, -100.2],
  "47": ["TN", "Tennessee", 35.9, -86.4], "48": ["TX", "Texas", 31.5, -99.3], "49": ["UT", "Utah", 39.3, -111.7],
  "50": ["VT", "Vermont", 44.1, -72.7], "51": ["VA", "Virginia", 37.5, -78.8], "53": ["WA", "Washington", 47.4, -120.5],
  "54": ["WV", "West Virginia", 38.6, -80.6], "55": ["WI", "Wisconsin", 44.6, -89.9], "56": ["WY", "Wyoming", 43.0, -107.5],
  // territories: their own ISO country codes
  "66": ["GU", "Guam", 13.45, 144.8, "GU"], "72": ["PR", "Puerto Rico", 18.2, -66.5, "PR"], "78": ["VI", "U.S. Virgin Islands", 18.0, -64.8, "VI"],
};
/** Postal abbreviation -> { fips, abbr, name, lat, lng, country }. */
export const BY_ABBR = Object.fromEntries(Object.entries(US_STATES).map(([fips, [abbr, name, lat, lng, cc]]) =>
  [abbr, { fips, abbr, name, lat, lng, country: cc || "US" }]));
/** County FIPS (5 digits) or state FIPS (2) -> the state record, or null. */
export function stateOfFips(code) {
  const m = String(code == null ? "" : code).trim().match(/^(\d{2})(\d{3})?$/);
  const s = m && US_STATES[m[1]];
  return s ? BY_ABBR[s[0]] : null;
}
/** "MID-WILSHIRE" -> "Mid-Wilshire", "WEST HARTFORD" -> "West Hartford" (display only). */
export const titleCase = (s) => String(s == null ? "" : s).toLowerCase().replace(/(^|[\s\-/'(])([a-z])/g, (_, a, b) => a + b.toUpperCase());

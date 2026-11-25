# Menu pages redesign (2026-11-25)

## Intent

The menu pages (Vulnerabilities, Tools, Archive, Trends, Actors, Exercise, Community, Status, About) left most of a desktop screen empty: everything sat in a 1040px column. Trends, Status and the other data views did not read clearly. The owner wants a defender who lands on any page to see the whole picture at once, to be able to explore it, and to have the messages stay clear. Every page should be searchable, look professional and keep CyberView's smoked-glass look: translucent blurred panels, rounded pill controls, no square buttons.

## Goals

- Pages fill the width of the screen, with comfortable gutters (24–32px).
- Each page starts with a "situation at a glance" band (KPIs or a summary) and then shows question-led, interactive modules (direction B), each tailored to its page.
- Every page has a search field.
- Vulnerabilities becomes a three-pane database: a filter rail, a dense CVE table and a detail pane. The table fills the screen down to the bottom edge and scrolls inside its own pane (owner, 2026-11-25), so the page itself does not scroll on desktop.
- The glass look is the same as the map page: the same tokens, panels, pill navigation, pill buttons and segmented tabs.
- On phones every page flows to a single column with no sideways scrolling.

## Non-goals

- No change to what data is collected, how it is checked or what the pipeline writes.
- No new chart colours. Bars stay single-colour (rule 5), and the category palette is not changed (rule 4).
- No viewer workflow state (rule 6).

## Constraints

The CSP and DOM rules, `safe()` panels, the inventory staying in the browser only (rule 11), the AI label (rule 15), and the existing class names. The legal pages and the account pages share `archive.css`, so the shared layer must not break them.

## Approaches

1. **A shared glass layer at the end of `archive.css` plus per-page rebuilds (chosen).** It overrides the tokens, the width of `main`, panels, rows, buttons, tabs and inputs for every page at once. Each data page then gets its own board markup. This has the least risk to pages nobody touches, and every page gets the look straight away.
2. **A new stylesheet per page.** This gives the most freedom but duplicates the glass rules nine times, and they drift apart.
3. **A component framework.** Ruled out: the site is static, its scripts are CSP-locked, and it has no build step for UI code.

## Per page

- **Trends:** a KPI band (this week, the week before, the change, the busiest day), a 28-day chart with a round-step y-axis and gridlines, ranked mover tables in a responsive grid, and a search that filters every table. The power-grid context panel and its caveat are kept.
- **Vulnerabilities:** the three panes on desktop (≥1240px), and two below that (the detail pane opens over the table). The five tabs stay as segmented pills. The table is a viewport-height pane with its own scroll.
- **Status, Archive, Actors, Exercise, Community, About, Tools:** full width, glass panels, a summary band where data allows, and search.

## Left to the builder

Exact breakpoints, KPI choices per page and where search lives on each page, as long as the goals and constraints above hold.

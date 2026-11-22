# Handoff: scan-dep-map

Stage A infers edges from one report: co-location is low confidence, an in-scope redirect is medium, and any other name is "mentioned, not scanned". Stage C reads a connections file. It does not log in and it does not probe. Outputs: graph.json, Mermaid, Graphviz, and a self-contained HTML table.

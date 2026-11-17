# Authorized use only

This project is for security testing you are authorized to perform: your own
assets, or a bug-bounty / pentest engagement whose scope you have confirmed in
writing. Unauthorized testing is illegal.

- Every host is checked against your `scope.txt`; out-of-scope hosts are skipped.
- The tool DETECTS and DRAFTS. It does not auto-exploit. Chaining PoCs
  (XSS, session fixation, open redirect, cache poisoning, SSRF->RCE) are manual
  templates you run yourself, in scope, after confirming reachability.
- The AI report is a drafting aid, not proof. Reproduce every finding by hand
  before disclosure, and claim only impact you have demonstrated.

You are solely responsible for your actions and for staying within scope and
the law.

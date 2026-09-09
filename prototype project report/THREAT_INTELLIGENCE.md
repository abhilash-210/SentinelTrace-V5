# Threat Intelligence Module

## IOC Ingestion & Normalization
Ingests IP addresses, domain names, file hashes (MD5, SHA-256), and URLs from threat feeds. Automatically normalizes indicators into OCSF Threat Intel classes.

## Invariant: IOC MATCH != CONFIRMED INCIDENT
A match against a threat intelligence indicator triggers elevated risk correlation and scoring, but does not automatically convert into a confirmed security incident until contextual detection and risk threshold rules are satisfied.

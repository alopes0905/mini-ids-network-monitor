# Threat Model

This document defines the defensive and ethical scope of the Mini IDS / Network Security Monitor.

## Current Status

The project implements offline PCAP analysis with metadata parsing, three heuristic detection-rule families, structured logs, traffic summaries, and JSON reports. Live capture, automated response, and payload-signature detection are not implemented.

## Purpose

Mini IDS helps analyze authorized network traffic captures for simple suspicious patterns. It is an educational defensive monitoring project, not a production IDS replacement.

## Authorized Use

Use this tool only with:

- PCAP files you created
- Lab traffic you generated
- Traffic captures you are explicitly authorized to analyze
- Public educational PCAPs that are safe and properly attributed

## Out of Scope

This project must not implement:

- Packet injection
- Exploitation
- Brute-force tooling
- Credential extraction
- Malware behavior
- Payload stealing
- Automatic attack execution
- Firewall modification as an initial feature
- Offensive scanning modules
- Deep inspection of sensitive payloads

## Detection Scope

The implemented detection scope is intentionally narrow:

- Port scan-like behavior
- TCP connection-attempt bursts
- DNS query bursts, unique-domain bursts, and long queried domains

## Limitations

Mini IDS will be a lightweight educational tool. It should not claim to replace mature tools such as Suricata, Snort, or Zeek.

Expected limitations include:

- Limited protocol coverage
- Simple threshold-based detections
- Possible false positives
- No encrypted traffic decryption
- No enterprise-scale monitoring guarantees

## Ethical Boundary

The project should remain passive, defensive, transparent, and educational throughout development.

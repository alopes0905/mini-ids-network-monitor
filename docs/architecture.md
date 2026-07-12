# Architecture

This document will describe the high-level design of the Mini IDS / Network Security Monitor.

## Current Status

Architecture placeholder only. No parser, engine, rules, CLI, logging, configuration, or reporting logic has been implemented yet. The repository currently has the initial package structure, dependency list, and package import smoke test.

## Planned Data Flow

```text
Packet Source
    -> Packet Parser
    -> PacketInfo model
    -> Detection Engine
    -> Detection Rules
    -> Alert model
    -> Logger / Reporter
    -> CLI Output / JSON Logs / Reports
```

## Planned Components

### Packet Source

Planned responsibility: read packets from offline PCAP files first, with optional live capture later.

### Packet Parser

Planned responsibility: convert raw packets into a small internal metadata model.

### Data Models

Planned responsibility: represent parsed packet metadata and generated alerts in consistent structures.

### Detection Engine

Planned responsibility: pass packet metadata through enabled detection rules and collect alerts.

### Detection Rules

Planned responsibility: detect focused suspicious behaviors such as port scans and connection bursts.

### Logging and Reporting

Planned responsibility: save structured alerts and later generate analysis summaries.

### CLI

Planned responsibility: provide a clean command-line interface for running offline analysis.

## Design Notes

- Keep raw packet handling isolated from detection logic.
- Keep rules small, explicit, and testable.
- Prefer clear data models over passing loosely shaped dictionaries everywhere.
- Start with offline PCAP analysis before live capture.

## Development Setup

Development dependencies are listed in `requirements.txt`. Use a local virtual environment and run `python -m pytest` from the repository root to verify the current smoke test.

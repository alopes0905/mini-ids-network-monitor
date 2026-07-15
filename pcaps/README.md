# PCAP Files

This directory is reserved for local PCAP files used during development and demos.

Do not commit real private network captures. PCAP files can contain sensitive metadata, hostnames, internal IP addresses, credentials, or payload data.

Safe options:

- Generate tiny synthetic PCAP files for tests.
- Use lab traffic that contains no private data.
- Use public educational PCAPs only when their license and attribution allow it.
- Prefer documenting where to get sample captures instead of committing captures directly.

The project can currently read raw packets from offline PCAP files, but it does not yet parse packet metadata, analyze traffic, or detect threats.

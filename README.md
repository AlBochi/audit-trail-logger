# Audit Trail Logger

A lightweight model decision logging system for audit readiness. Built for financial institutions that need to demonstrate traceability under OSFI E-23 and SR 11-7.

## What It Does

- Logs every model decision with timestamp, input parameters, and output
- Tracks model version, data source, and confidence score per prediction
- Generates immutable audit logs in JSON format
- Supports real-time streaming to dashboards

## Quick Start

git clone https://github.com/AlBochi/audit-trail-logger.git
cd audit-trail-logger
pip install -r requirements.txt
python logger.py --model credit-risk-v3 --env production

## Regulatory Alignment

- OSFI E-23 Audit Trail Requirements
- SR 11-7 Ongoing Monitoring Standards
- SEC Recordkeeping Requirements

## Status

Proof of concept by Saillent.

## License

MIT

# VulnWeaver

Educational Payload Generation Framework
Offensive Security Internship Project – ITSOLERA (PVT) LTD

## Overview

VulnWeaver is a modular, educational payload generation framework designed to demonstrate:

How attackers exploit common web vulnerabilities
How WAFs and input filters respond
Why naive filtering fails
How modern defenses mitigate these attacks
This tool does NOT send live attack traffic.
It generates payload templates

## Project Objectives

This framework was built to satisfy the ITSOLERA Offensive Security Internship task requirements:

Modular CLI-based architecture
Educational payload templates (non-operational by default)
Encoding demonstrations
Obfuscation logic
Export support (JSON / TXT / CSV)
Burp Intruder compatible export

## Usage Guide

This section explains how to install, configure, and properly use VulnWeaver in both educational and lab environments.

#### Requirements

Python 3.7+
Kali Linux (recommended) or any Linux/macOS/Windows environment
DVWA or OWASP Juice Shop (for testing)

#### Installation

Clone the Repository

```shell
git clone https://github.com/dhaliaeid/VulnWeaver.git
cd VulnWeaver
```

#### Basic Command Structure

python3 vw.py --module <module_name> [options]
General Syntax:

```scss
python vw.py
    --module {xss,sqli,cmdi,all}
    --mode {template,lab}
    --encode {url,base64,hex,none}
    --db {mysql,postgresql,mssql}
    --os {linux,windows,both}
    --obfuscate {comment,whitespace,mixed}
    --output <file>
    --format {json,txt,csv}
    --burp
    --test-xss
    --test-sqli
    --test-cmdi
```

#### Module Usage Examples

#### XSS Module

Generate Educational Templates

```bash
python vw.py --module xss
```

With Encoding Demonstration

```bash
python vw.py --module xss --encode url
```

#### SQL Injection Module

MySQL Payloads

```bash
python vw.py --module sqli --db mysql
```

PostgreSQL Payloads

```bash
python vw.py --module sqli --db postgresql
```

With Obfuscation Concept

```bash
python vw.py --module sqli --obfuscate comment
```

#### Command Injection Module

Linux Patterns

```bash
python vw.py --module cmdi --os linux
```

Windows Patterns

```bash
python vw.py --module cmdi --os windows
```

#### Exporting Payloads

JSON Export

```bash
python vw.py --module all --output payloads.json --format json
```

Text Catalog Export

```bash
python vw.py --module xss --output catalog --format txt
```

CSV Export

```bash
python vw.py --module sqli --output sqli --format csv
```

Burp Suite Intruder Format

```bash
python vw.py --module xss --burp --output burp_payloads.txt
```

Load the generated file in:

```bash
Burp → Intruder → Payloads → Load from file
```

## Testing with DVWA (Recommended Workflow)

Start DVWA
Set Security Level to "Low"
Generate payload:

```bash
python vw.py --test-xss
```

Inject payload into vulnerable field
Capture screenshot
Document behavior and defensive explanation

## Safety Guidelines

Never test against systems without written authorization
Use only local lab environments
Do not automate exploitation
This tool does not send HTTP requests

## Getting Help

View CLI help menu:

```bash
python vw.py -h
```

Show usage examples:

```bash
python vw.py --examples
```

## Author

Dalia Ibrahim
Offensive Security Intern
ITSOLERA (PVT) LTD

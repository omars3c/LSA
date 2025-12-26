# LSA - Lightweight AWS Security Auditor

### Description
LSA is a small CLI tool that quickly highlights common AWS security misconfigurations across **S3**, **EC2**, and **IAM**. It’s built for pentesters and DevOps engineers who want a fast “sanity check” before (or during) a security review.

### Installation

```bash
git clone <your-repo-url>
cd <repo-folder>

python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

pip install -r requirements.txt
```

### Usage

```bash
# If you installed dependencies inside a venv, use the same interpreter:
python main.py --help

# Run everything (default is all)
python main.py --service all

# Run a single service
python main.py --service ec2
python main.py --service s3
python main.py --service iam

# Pick a region (default: us-east-1)
python main.py --service s3 --region us-west-1
python main.py --service ec2 --region eu-central-1
```

#### What to expect
- If AWS credentials/permissions are missing, the tool prints a red error telling you to configure AWS CLI.
- When configured, it prints tables per service (S3 bucket exposure, EC2 SG ingress, IAM MFA/key hygiene).

#### Run demo tests without AWS keys (recommended)
The repository includes Moto-powered tests that emulate AWS APIs locally:

```bash
python test_audit.py
```

### Key Features & Capabilities

1. S3 Data Leakage Detection (S3 Hunter)

    Deep Inspection: Doesn't just check the bucket name. It verifies Public Access Block settings and parses Access Control Lists (ACLs).

    Critical Alerts: Instantly flags buckets granting AllUsers (Public Read/Write) permissions.

    Goal: Prevents accidental data exposure and "S3 Leaks" that lead to data breaches.

2. Network Perimeter Analysis (EC2/SG)

    Attack Surface Mapping: Scans all Security Groups for "wide open" rules (0.0.0.0/0).

    Port Intelligence: Specifically hunts for high-risk management ports exposed to the internet:

        22 (SSH) - Brute-force risk.

        3389 (RDP) - Ransomware entry point.

        3306/5432 (Databases) - SQL Injection/Data exfiltration risk.

3. IAM Privilege Hygiene

    MFA Audit: Identifies users (especially administrators) with console access but no Multi-Factor Authentication enabled. (Top cause of account takeovers).

    Stale Key Detection: Highlights Access Keys that have been active and unrotated for >90 days, helping you maintain compliance standards (CIS/NIST).

### Disclaimer
This project is provided for **educational purposes** and for auditing **your own** infrastructure (or systems you have explicit permission to test). You are responsible for how you use it. The authors and contributors are not liable for any damages or misuse.



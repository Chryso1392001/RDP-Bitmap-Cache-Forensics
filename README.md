🐙 GitHub – Repository Description (Top-Level)
RDP Bitmap Cache Forensics

Windows RDP Screen Artifact Discovery, Extraction & Secure Deletion

This project demonstrates a critical but under-documented Windows security risk:
Remote Desktop Protocol (RDP) bitmap cache persistence on client systems.

Windows stores rendered screen fragments from RDP sessions locally. These artifacts:

Persist indefinitely after session termination

Are accessible to standard users

Can be reconstructed into meaningful screen content

Are not monitored or cleaned by default security tools

🚨 Why This Matters

If an endpoint is compromised, an attacker can:

Extract historical RDP session data

Reconstruct admin activity visually

Recover credentials, commands, file paths, and sensitive business data

Operate silently with no EDR or SIEM alerts

This technique provides higher intelligence value than keylogging with lower detection risk.

🔬 Features

🔍 Automatic discovery of RDP bitmap cache locations

📊 Cache size, age, and risk assessment

🧩 Bitmap tile extraction for forensic analysis

🗑️ Secure deletion (multi-pass overwrite)

📁 Evidence preservation for DFIR workflows

⚙️ Designed for IR, threat hunting, and proactive defense

🧪 Tested Environment

Client: Windows 11 Enterprise

Target: Windows Server (RDP)

Access Level: Standard user

Python: 3.x

📂 Default Cache Location
C:\Users\<USER>\AppData\Local\Microsoft\Terminal Server Client\Cache


Typical files:

Cache0000.bin

Cache0001.bin

bcache*.bmc

⚔️ Threat Model
Attacker Capabilities

Local file system access

No admin privileges required

Offline reconstruction of screen artifacts

Defender Use Cases

Incident response scope assessment

Threat hunting for silent data exposure

Admin workstation hardening

Compliance & audit evidence

Security awareness demonstrations

🛡️ Defensive Recommendation

Organizations should:

Regularly audit RDP bitmap cache directories

Implement automated cleanup

Treat RDP cache as sensitive data at rest

Include this artifact in IR playbooks

📜 Disclaimer

This tool is provided for educational, research, and defensive security purposes only.
Use only on systems you own or have explicit authorization to test.

⭐ Contributing

Contributions, issues, and improvements are welcome.
If you’re interested in extending this for:

EDR integration

Enterprise automation

Cache reconstruction tooling

Detection engineering

Feel free to open an issue or PR.

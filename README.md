# CLOSEDQUORUM Mitigation and Detection

Defensive countermeasures and behavioral detections for the **CLOSEDQUORUM** Windows implant. As detailed by Cisco Talos, this malware utilizes an autonomous "quorum" of LLMs (DeepSeek, Qwen, Mistral, Gemini) to vote on post-compromise actions, removing the need for a human operator.

Because this threat relies on injected API keys and daily-rotating AES-256-GCM encryption for its Discord-based exfiltration, traditional IoC blocking is largely ineffective. This repository focuses on behavioral detection and environmental hardening.

## Repository Contents

* **`Mitigate-ClosedQuorum.ps1`**: A PowerShell script requiring Administrator privileges that neutralizes the malware's defined capability modules:
  * **Steal**: Blocks LSASS dumping by enforcing LSA Protection.
  * **Inject & Persist**: Blocks process hollowing and WMI persistence via targeted ASR rules.
  * **C2**: (Optional) Null-routes known LLM API voting endpoints via the Windows hosts file.
* **`win_closedquorum_ai_c2.yml`**: A Sigma rule to detect the behavioral loop of a process querying multiple AI model APIs followed by malicious system hooks.

## Usage

1. **Detection:** Compile the Sigma rule into your target SIEM/EDR query language (e.g., Splunk, KQL, Elastic) using `sigmac` or Uncoder.io.
2. **Mitigation:** Run the PowerShell script on target endpoints. 
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\Mitigate-ClosedQuorum.ps1

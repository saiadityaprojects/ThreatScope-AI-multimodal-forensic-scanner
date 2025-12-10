================================================================

&nbsp; THREATSCOPE AI - MULTIMODAL FORENSIC SCANNER

================================================================



> A Next-Gen Forensic Tool for Phishing, Document, and Vishing Analysis.

> Powered by React 19, Vite, and Google Gemini 1.5 Flash.



----------------------------------------------------------------

&nbsp; 1. PROJECT OVERVIEW

----------------------------------------------------------------

ThreatScope AI is a cybersecurity forensic dashboard designed to bridge the gap

between victim safety and technical investigation.



Unlike standard scanners that only look at text, ThreatScope uses Multimodal AI to analyze:

\* Emails \& Text: Header analysis, SPF/DKIM verification, and intent detection.

\* Documents (PDF/Office): Scanning for suspicious macros and embedded scripts.

\* Audio (MP3): Vishing (Voice Phishing) detection to flag urgency/fake authority.



The application features a unique Dual-Mode Interface:

&nbsp; \[1] Civilian Mode: Simplified, jargon-free actionable advice for victims.

&nbsp; \[2] SOC Analyst Mode: Deep technical forensics including IOCs, MITRE ATT\&CK, and IP Geolocation.



----------------------------------------------------------------

&nbsp; 2. KEY FEATURES

----------------------------------------------------------------

\* Multimodal Engine: One drag-and-drop interface for Text, Files, and Audio.

\* AI-Powered Analysis: Uses Google Gemini 1.5 Flash for context-aware detection.

\* Threat Intelligence: Integrated IP geolocation and confidence scoring.

\* Phishing Dojo: A gamified "Training Mode" to help users practice spotting threats.

\* Real-Time Reporting: Generates instant "Clean," "Suspicious," or "Malicious" verdicts.



----------------------------------------------------------------

&nbsp; 3. INSTALLATION \& SETUP

----------------------------------------------------------------

**Note to Judges: The "node\_modules" folder has been excluded to optimize file size.**

Please follow these steps to run the application:



STEP 1: Unzip and Open Terminal

&nbsp;  Navigate to the project directory:

&nbsp;  cd PHISHING-EMAIL-FORENSICS



STEP 2: Install Dependencies

&nbsp;  Run this command to download necessary libraries:

&nbsp;  npm install



STEP 3: Configure API Key

&nbsp;  Create a file named ".env.local" in the root directory.

&nbsp;  Paste your Google Gemini API Key inside it like this:

&nbsp;  VITE\_GEMINI\_API\_KEY=your\_actual\_api\_key\_here



STEP 4: Run the Application

&nbsp;  Start the local server:

&nbsp;  npm run dev



&nbsp;  Then open the link shown (usually http://localhost:5173).



----------------------------------------------------------------

&nbsp; 4. TECH STACK

----------------------------------------------------------------

\* Frontend: React 19, Vite, TypeScript

\* Styling: TailwindCSS, Framer Motion

\* AI Backend: Google Generative AI SDK (Gemini 1.5 Flash)

\* Mapping: Pigeon Maps

\* Icons: Lucide React



----------------------------------------------------------------

&nbsp; DISCLAIMER

----------------------------------------------------------------

This tool is a Proof of Concept (PoC) developed for educational and hackathon purposes.

It uses client-side API calls for demonstration. In a real-world enterprise deployment,

API keys and logic would be secured via a backend proxy.



----------------------------------------------------------------


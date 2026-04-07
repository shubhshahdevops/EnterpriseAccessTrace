# Enterprise Access Trace

Enterprise Access Trace is a desktop-based analysis tool designed to provide visibility into file system permissions, identify access paths, and detect permission drift across enterprise environments.

The tool combines automated scanning, structured data processing, and a GUI-based reporting interface to transform complex access control data into actionable insights.

## Overview

In enterprise environments, access control structures often become difficult to audit due to nested group memberships, inherited permissions, legacy access rules, and lack of centralized visibility.

Enterprise Access Trace addresses these challenges by scanning file system ACLs, correlating identities with access rights, and presenting results in a structured, human-readable format.

## Key Capabilities

Permission Discovery  
Scans directories recursively and extracts detailed Access Control List (ACL) information including identities, rights, inheritance, and propagation rules.

Target-Based Access Tracing  
Allows administrators to define specific users or groups and trace their effective access across the scanned environment.

Permission Drift Detection  
Identifies potentially risky configurations such as broad access assignments (e.g., Everyone, Users, Authenticated Users) and flags them for review.

Structured Reporting  
Generates an interactive HTML report that includes summary metrics, access path mappings, drift findings, and contextual explanations.

Desktop GUI Interface  
Provides a user-friendly interface that abstracts command-line complexity and enables execution through a simple workflow.

## Architecture

The solution consists of three components:

Scanner (PowerShell)  
Collects ACL data and exports structured datasets in JSON and CSV formats.

Application Layer (Python)  
Processes scan results and builds the report.

GUI (PySide6)  
Provides the execution interface for configuration and running analysis.

## Technology Stack

Python (application logic and GUI)  
PowerShell (permission scanning)  
PySide6 (desktop interface)  
HTML and CSS (report generation)  
JSON and CSV (data exchange)

## Installation and Setup

Prerequisites  
Python 3.9 or higher  
PowerShell 5.1 or higher  
Windows environment  

Steps  
1. Clone the repository  
   git clone https://github.com/shubhshahdevops/EnterpriseAccessTrace.git  

2. Navigate to the project folder  
   cd EnterpriseAccessTrace  

3. Install dependencies  
   pip install -r requirements.txt  

## Usage

1. Launch the application  
   python app/main.py  

2. Configure the scan  
   Select the root folder  
   Select the output folder  
   Enter target identities if needed (e.g., Users, Administrators)  
   Enable drift analysis if required  

3. Run the scan  

4. Open the generated report  
   sample-output/report.html  

## Sample Output

The report includes total ACL records analyzed, access paths for selected targets, drift findings categorized by severity, and contextual explanations of access.

## Use Cases

File server access audits  
Permission troubleshooting  
Security reviews and compliance checks  
Identifying excessive or unintended access  
Supporting IT and security investigations  

## Limitations

Currently limited to NTFS file system permissions  
No Active Directory group expansion yet  
No direct Microsoft 365 or SharePoint integration  

## Future Enhancements

Active Directory integration  
Microsoft 365 and SharePoint support  
Graph-based access visualization  
Risk scoring system  
Export to enterprise dashboards  

## Project Motivation

This project was developed to address the lack of clear visibility into permission structures in complex environments. The goal is to move beyond listing permissions and instead explain why access exists.

## License

This project is intended for educational and demonstration purposes.

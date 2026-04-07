# 🚀 Enterprise Access Trace

Enterprise Access Trace is a desktop-based access intelligence tool designed to analyze, explain, and visualize permission structures across file systems.

It helps answer a critical enterprise question:

> **Who has access to what — and why?**

---

## 🧠 Problem Statement

In enterprise environments, permissions are often:
- spread across folders, groups, and inherited structures
- difficult to trace manually
- prone to **permission drift** over time

This leads to:
- overexposed data
- unclear access ownership
- security and audit challenges

---

## 💡 Solution

Enterprise Access Trace automates permission analysis and transforms raw ACL data into a structured, explainable report.

The system:
- scans file system permissions (NTFS)
- extracts ACL records
- matches access paths for target identities
- detects broad access patterns
- generates an interactive HTML dashboard

---

## ⚙️ Features

### 🔍 Permission Scanning
- Recursive scan of folders and files
- Reads NTFS ACLs using PowerShell
- Captures identities, rights, inheritance, and access type

### 👤 Access Path Matching
- Matches user-defined targets (e.g., Users, Administrators)
- Identifies where and how access exists
- Handles partial and domain-style identity matches

### ⚠️ Drift Detection
- Detects broad access identities:
  - `Users`
  - `Everyone`
  - `Authenticated Users`
- Flags potential overexposure

### 📊 Enterprise HTML Report
- Summary dashboard
- Permission distribution charts
- Identity analysis
- Drift findings with severity badges
- ACL preview tables

### 🖥️ Desktop GUI
- Built with PySide6
- Fully local execution
- No command-line required
- User-friendly scan configuration

---

## 🏗️ Architecture

```text
Python GUI (PySide6)
        ↓
PowerShell Scanner
        ↓
JSON / CSV Data
        ↓
Python Report Builder
        ↓
HTML Dashboard
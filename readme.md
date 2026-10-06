# 🔐 FormaLex

### Grammar-Based URL Phishing Detection Using Finite Automata

> An explainable URL phishing detection system that combines **Finite Automata, Context-Free Grammars, lexical analysis, and rule-based security detection**.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)
![Next.js](https://img.shields.io/badge/Next.js-Frontend-black)
![Automata](https://img.shields.io/badge/Finite%20Automata-DFA%20%7C%20CFG-purple)

---

# 📖 Overview

FormaLex analyzes URLs using formal language concepts to determine whether they are **likely legitimate, suspicious, or invalid**.

The system validates URL structure using a **DFA**, converts URLs into lexical tokens, checks **CFG membership**, and applies phishing detection rules.

---

# ✨ Features

- 🔄 DFA-based URL validation
- 🔤 URL lexical tokenization
- 📚 Legitimate URL CFG
- 🚨 Phishing grammars
- 🔍 Typosquatting & Leetspeak detection
- 🌐 IP-as-domain detection
- 🧬 Homoglyph / mixed-script detection
- 🌳 Excessive subdomain detection
- 🔑 Suspicious login-pattern detection
- 🌳 Explainable CFG parse trees
- 🧭 DFA state-path visualization

---

# 🏗️ Architecture

```text
             URL
              │
              ▼
          ┌───────┐
          │  DFA  │
          └───┬───┘
              │
              ▼
         Tokenization
              │
       ┌──────┴──────┐
       ▼             ▼
 Legitimate CFG   Phishing CFGs
       │             │
       └──────┬──────┘
              ▼
       Security Rules
              │
              ▼
           Verdict

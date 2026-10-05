# FormaLex

## Grammar-Based URL Phishing Detection Using Finite Automata

FormaLex is a web-based URL phishing detection system based on formal language concepts.

Instead of depending mainly on machine learning, FormaLex analyzes URL structure using:

- DFA-based URL analysis
- URL lexical tokenization
- Grammar-based URL representation
- Membership-style rule checking
- Phishing pattern detection
- Automaton state tracing
- Parse tree generation
- Explainable detection results

---

## Architecture

```text
URL Input
    |
    v
URL Normalization
    |
    v
DFA Lexer
    |
    v
Tokenization
    |
    v
Grammar / Phishing Rules
    |
    v
Membership Checking
    |
    v
State Path + Parse Tree
    |
    v
Final Verdict
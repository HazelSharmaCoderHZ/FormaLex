"use client";

import { useState } from "react";

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyzeURL = async () => {
    if (!url.trim()) return;

    setLoading(true);
    setResult(null);

    try {
      const response = await fetch("http://127.0.0.1:8000/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();
      setResult(data);
    } catch (error) {
      setResult({
        verdict: "ERROR",
        explanation: "Could not connect to FormaLex backend.",
      });
    }

    setLoading(false);
  };

  return (
    <main className="container">
      <div className="hero">
        <div className="badge">FORMAL LANGUAGE SECURITY</div>

        <h1>
          Forma<span>Lex</span>
        </h1>

        <p className="subtitle">
          Grammar-Based URL Phishing Detection Using Finite Automata
        </p>

        <div className="input-section">
          <input
            type="text"
            placeholder="Enter a URL to analyze..."
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") analyzeURL();
            }}
          />

          <button onClick={analyzeURL} disabled={loading}>
            {loading ? "Analyzing..." : "Analyze URL"}
          </button>
        </div>

        <div className="examples">
          Try:
          <button onClick={() => setUrl("https://example.com/products")}>
            Legitimate
          </button>
          <button onClick={() => setUrl("https://paypa1.com/login")}>
            Typosquatting
          </button>
          <button onClick={() => setUrl("https://192.168.1.10/login")}>
            IP Domain
          </button>
        </div>
      </div>

      {result && (
        <div className="results">

          <section className="verdict-card">
            <div>
              <p className="section-label">FINAL VERDICT</p>

              <h2
                className={
                  result.verdict === "LIKELY_LEGITIMATE"
                    ? "safe"
                    : result.verdict === "SUSPICIOUS"
                    ? "danger"
                    : "warning"
                }
              >
                {result.verdict}
              </h2>
            </div>

            {result.attack_type && (
              <div className="attack">
                <span>ATTACK TYPE</span>
                <strong>{result.attack_type}</strong>
              </div>
            )}
          </section>

          <section className="card">
            <h3>Explanation</h3>
            <p>{result.explanation}</p>

            <div className="rule">
              <span>Matched Rule</span>
              <strong>{result.rule}</strong>
            </div>
          </section>

          <section className="card">
            <h3>URL Tokens</h3>

            <div className="tokens">
              {result.tokens?.map((token, index) => (
                <div className="token" key={index}>
                  <span>{token.type}</span>
                  <strong>{token.value}</strong>
                </div>
              ))}
            </div>
          </section>

          <section className="card">
            <h3>DFA State Path</h3>

            <div className="state-path">
              {result.state_path?.map((state, index) => (
                <div className="state-wrapper" key={index}>
                  <div className="state">{state}</div>

                  {index < result.state_path.length - 1 && (
                    <div className="arrow">→</div>
                  )}
                </div>
              ))}
            </div>
          </section>

          <section className="card">
            <h3>Parse Tree</h3>

            <ParseTree node={result.parse_tree} />
          </section>

        </div>
      )}
    </main>
  );
}


function ParseTree({ node, level = 0 }) {
  if (!node) return null;

  return (
    <div className="tree-node" style={{ marginLeft: level * 25 }}>
      <div className="tree-box">
        {node.symbol}
      </div>

      {node.children?.map((child, index) => (
        <ParseTree
          key={index}
          node={child}
          level={level + 1}
        />
      ))}
    </div>
  );
}
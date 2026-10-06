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
              <h3>Formal Language Analysis</h3>

              <div className="formal-grid">

                <div className="formal-item">
                  <span>Legitimate CFG</span>
                  <strong
                    className={
                      result.grammar_membership ? "safe" : "danger"
                    }
                  >
                    {result.grammar_membership
                      ? "ACCEPTED"
                      : "REJECTED"}
                  </strong>
                </div>

                <div className="formal-item">
                  <span>Phishing Grammars</span>
                  <strong>
                    {result.phishing_grammar_matches?.length || 0}
                    {" "}matched
                  </strong>
                </div>

              </div>

              {result.phishing_grammar_matches?.length > 0 && (
                <div className="grammar-matches">

                  <p className="section-label">
                    MATCHED PHISHING GRAMMARS
                  </p>

                  {result.phishing_grammar_matches.map(
                    (match, index) => (
                      <div
                        className="grammar-match"
                        key={index}
                      >
                        {match.type}
                      </div>
                    )
                  )}

                </div>
              )}
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
            <h3>CFG Parse Tree</h3>

            {result.parse_tree ? (
              <ParseTree node={result.parse_tree} />
            ) : (
              <p>No parse tree available.</p>
            )}
          </section>

        </div>
      )}
    </main>
  );
}

function ParseTree({ node, level = 0 }) {
  if (!node) return null;

  return (
    <div
      className="tree-node"
      style={{ marginLeft: `${level * 30}px` }}
    >
      <div className="tree-box">
        <strong>{node.symbol}</strong>
      </div>

      {node.children?.map((child, index) => (
        <div key={index}>
          <div className="tree-connector">↓</div>

          <ParseTree
            node={child}
            level={level + 1}
          />
        </div>
      ))}
    </div>
  );
}
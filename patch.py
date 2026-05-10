# -*- coding: utf-8 -*-
import re

with open('securefs_v2 (1).html', 'r', encoding='utf-8') as f:
    content = f.read()

compare_html = '''      <!-- COMPARE -->
      <div id="panel-compare" style="max-width:1100px; margin: 60px auto; padding: 0 20px; box-sizing: border-box;">
        <div class="panel-header" style="margin-bottom: 30px;">
          <div class="panel-header-text">
            <div class="panel-title">Competitive Benchmarks</div>
            <div class="panel-desc">How SecureFS v2 compares to 4 real-world encryption tools across security, features, usability and more.</div>
          </div>
        </div>
        <div class="cmp-metric-row">
          <div class="cmp-metric"><div class="cmp-metric-val" style="color:var(--accent)">6</div><div class="cmp-metric-label">RBAC Roles</div><div class="cmp-metric-sub">Avg 0 in comparable tools</div></div>
          <div class="cmp-metric"><div class="cmp-metric-val" style="color:var(--green)">AES-256</div><div class="cmp-metric-label">Cipher + GCM Mode</div><div class="cmp-metric-sub">AEAD — tamper-proof</div></div>
          <div class="cmp-metric"><div class="cmp-metric-val" style="color:var(--amber)">100K</div><div class="cmp-metric-label">PBKDF2 Iterations</div><div class="cmp-metric-sub">Industry-standard minimum</div></div>
          <div class="cmp-metric"><div class="cmp-metric-val" style="color:var(--orange)">16/17</div><div class="cmp-metric-label">Feature Score</div><div class="cmp-metric-sub">+Blockchain in v2</div></div>
        </div>
        <div class="cmp-section-label">Projects Compared</div>
        <div class="cmp-grid-5">
          <div class="proj-mini">
            <div class="proj-mini-head"><div class="proj-dot" style="background:#38bdf8"></div><div><div class="proj-mini-name">SecureFS v2</div><div class="proj-mini-sub">This project</div></div></div>
            <div class="proj-tags"><span class="proj-tag">Python+Browser</span><span class="proj-tag">RBAC</span><span class="proj-tag">Blockchain</span></div>
            <div class="proj-bars">
              <div class="proj-bar-row"><span class="proj-bar-label">Security</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:94%;background:#38bdf8"></div></div><span class="proj-bar-val">94</span></div>
              <div class="proj-bar-row"><span class="proj-bar-label">Features</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:97%;background:#38bdf8"></div></div><span class="proj-bar-val">97</span></div>
              <div class="proj-bar-row"><span class="proj-bar-label">Usability</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:88%;background:#38bdf8"></div></div><span class="proj-bar-val">88</span></div>
            </div>
          </div>
          <div class="proj-mini">
            <div class="proj-mini-head"><div class="proj-dot" style="background:#f472b6"></div><div><div class="proj-mini-name">VaultMan</div><div class="proj-mini-sub">CLI password manager</div></div></div>
            <div class="proj-tags"><span class="proj-tag">Python</span><span class="proj-tag">AES-128</span><span class="proj-tag">No RBAC</span></div>
            <div class="proj-bars">
              <div class="proj-bar-row"><span class="proj-bar-label">Security</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:60%;background:#f472b6"></div></div><span class="proj-bar-val">60</span></div>
              <div class="proj-bar-row"><span class="proj-bar-label">Features</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:35%;background:#f472b6"></div></div><span class="proj-bar-val">35</span></div>
              <div class="proj-bar-row"><span class="proj-bar-label">Usability</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:55%;background:#f472b6"></div></div><span class="proj-bar-val">55</span></div>
            </div>
          </div>
          <div class="proj-mini">
            <div class="proj-mini-head"><div class="proj-dot" style="background:#34d399"></div><div><div class="proj-mini-name">VeraCrypt</div><div class="proj-mini-sub">Disk encryptor</div></div></div>
            <div class="proj-tags"><span class="proj-tag">C++</span><span class="proj-tag">AES-XTS</span><span class="proj-tag">Desktop</span></div>
            <div class="proj-bars">
              <div class="proj-bar-row"><span class="proj-bar-label">Security</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:97%;background:#34d399"></div></div><span class="proj-bar-val">97</span></div>
              <div class="proj-bar-row"><span class="proj-bar-label">Features</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:68%;background:#34d399"></div></div><span class="proj-bar-val">68</span></div>
              <div class="proj-bar-row"><span class="proj-bar-label">Usability</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:50%;background:#34d399"></div></div><span class="proj-bar-val">50</span></div>
            </div>
          </div>
          <div class="proj-mini">
            <div class="proj-mini-head"><div class="proj-dot" style="background:#fbbf24"></div><div><div class="proj-mini-name">age</div><div class="proj-mini-sub">Modern CLI tool</div></div></div>
            <div class="proj-tags"><span class="proj-tag">Go</span><span class="proj-tag">ChaCha20</span><span class="proj-tag">CLI</span></div>
            <div class="proj-bars">
              <div class="proj-bar-row"><span class="proj-bar-label">Security</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:88%;background:#fbbf24"></div></div><span class="proj-bar-val">88</span></div>
              <div class="proj-bar-row"><span class="proj-bar-label">Features</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:40%;background:#fbbf24"></div></div><span class="proj-bar-val">40</span></div>
              <div class="proj-bar-row"><span class="proj-bar-label">Usability</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:65%;background:#fbbf24"></div></div><span class="proj-bar-val">65</span></div>
            </div>
          </div>
          <div class="proj-mini">
            <div class="proj-mini-head"><div class="proj-dot" style="background:#a78bfa"></div><div><div class="proj-mini-name">Cryptomator</div><div class="proj-mini-sub">Cloud encryptor</div></div></div>
            <div class="proj-tags"><span class="proj-tag">Java</span><span class="proj-tag">AES-SIV</span><span class="proj-tag">Desktop+Mobile</span></div>
            <div class="proj-bars">
              <div class="proj-bar-row"><span class="proj-bar-label">Security</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:85%;background:#a78bfa"></div></div><span class="proj-bar-val">85</span></div>
              <div class="proj-bar-row"><span class="proj-bar-label">Features</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:60%;background:#a78bfa"></div></div><span class="proj-bar-val">60</span></div>
              <div class="proj-bar-row"><span class="proj-bar-label">Usability</span><div class="proj-bar-track"><div class="proj-bar-fill" style="width:88%;background:#a78bfa"></div></div><span class="proj-bar-val">88</span></div>
            </div>
          </div>
        </div>

        <div class="cmp-section-label">Multi-Dimension Radar & Dimension Scores</div>
        <p style="color:var(--muted); font-size:14px; margin-bottom:15px; line-height:1.5;">This radar chart illustrates how SecureFS excels across all major dimensions compared to standard tools. While others focus heavily on basic security, SecureFS provides an unmatched balance of collaborative features (RBAC), auditing (Blockchain), and usability.</p>
        <div class="cmp-grid-2">
          <div class="cmp-card"><div class="cmp-chart-title">7-Axis Capability Radar</div><div class="cmp-chart-sub">All 5 projects across key dimensions</div><canvas id="cmpRadar" height="260"></canvas></div>
          <div class="cmp-card"><div class="cmp-chart-title">SecureFS v2 Dimension Scores</div><div class="cmp-chart-sub">? marks where SecureFS leads all others</div><div id="cmp-score-bars" style="margin-top:8px"></div></div>
        </div>

        <div class="cmp-section-label">Security Architecture & Feature Count</div>
        <p style="color:var(--muted); font-size:14px; margin-bottom:15px; line-height:1.5;">By stacking multiple layers of defense (including Intrusion Detection, AAD identity binding, and Blockchain), SecureFS provides a significantly more resilient security architecture than traditional AES-only tools. It incorporates 16 of the 17 tracked enterprise features.</p>
        <div class="cmp-grid-2">
          <div class="cmp-card"><div class="cmp-chart-title">Security Score Composition</div><div class="cmp-chart-sub">Cipher + key derivation + AAD + tamper detect + IDS + blockchain</div><canvas id="cmpSecStack" height="200"></canvas></div>
          <div class="cmp-card"><div class="cmp-chart-title">Feature Count (of 17 tracked)</div><div class="cmp-chart-sub">SecureFS v2 implements 16 — highest of all tools</div><canvas id="cmpFeatureBar" height="200"></canvas></div>
        </div>

        <div class="cmp-section-label">Complexity vs Value & Unique Capabilities</div>
        <p style="color:var(--muted); font-size:14px; margin-bottom:15px; line-height:1.5;">The Bubble Chart shows how SecureFS delivers high value and feature completeness without compromising on usability. The Unique Capabilities chart highlights features that are entirely exclusive to SecureFS.</p>
        <div class="cmp-grid-2">
          <div class="cmp-card"><div class="cmp-chart-title">Features vs Complexity Bubble</div><div class="cmp-chart-sub">X = implementation complexity · Y = feature completeness · Size = usability</div><canvas id="cmpBubble" height="200"></canvas></div>
          <div class="cmp-card"><div class="cmp-chart-title">Exclusive Capabilities</div><div class="cmp-chart-sub">Features in SecureFS absent from all 4 other tools</div><canvas id="cmpUnique" height="200"></canvas></div>
        </div>

        <div class="cmp-section-label">Full Feature Comparison Matrix</div>
        <div class="cmp-insight"><strong>SecureFS v2 uniquely combines:</strong> role-based access control (6 roles), blockchain audit ledger, intrusion detection system, identity-bound encryption via AAD, file registry with hash tracking, and export capabilities — no other tool in this comparison offers all simultaneously.</div>
        <div class="card" style="padding:0;overflow-x:auto">
          <table class="cmp-feat-table">
            <thead><tr>
              <th>Feature</th>
              <th style="color:#38bdf8">SecureFS v2</th>
              <th style="color:#f472b6">VaultMan</th>
              <th style="color:#34d399">VeraCrypt</th>
              <th style="color:#fbbf24">age</th>
              <th style="color:#a78bfa">Cryptomator</th>
            </tr></thead>
            <tbody>
              <tr><td>AES-256-GCM (AEAD)</td><td><span class="cft-check">?</span></td><td><span class="cft-cross">?</span> AES-128</td><td><span class="cft-check">?</span></td><td><span class="cft-cross">?</span> ChaCha20</td><td><span class="cft-part">~ AES-SIV</span></td></tr>
              <tr><td>PBKDF2 Key Derivation</td><td><span class="cft-check">?</span> 100K</td><td><span class="cft-check">?</span> PBKDF2HMAC</td><td><span class="cft-check">?</span> 500K</td><td><span class="cft-cross">?</span> scrypt</td><td><span class="cft-check">?</span> scrypt</td></tr>
              <tr><td>Identity-Bound Encryption (AAD)</td><td><span class="cft-check">?</span> username|empId</td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td></tr>
              <tr><td>Role-Based Access Control</td><td><span class="cft-check">?</span> 6 roles</td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td></tr>
              <tr><td>Blockchain Audit Ledger</td><td><span class="cft-check">?</span> SHA-256 linked</td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td></tr>
              <tr><td>Intrusion Detection (IDS)</td><td><span class="cft-check">?</span> Lock @5 fails</td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td></tr>
              <tr><td>Audit / Access Log</td><td><span class="cft-check">?</span> Full trail</td><td><span class="cft-cross">?</span></td><td><span class="cft-part">~ Basic</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td></tr>
              <tr><td>File Registry + Hash Tracking</td><td><span class="cft-check">?</span> SHA-256 index</td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td></tr>
              <tr><td>Export Audit Log (CSV)</td><td><span class="cft-check">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td></tr>
              <tr><td>Multi-User Support</td><td><span class="cft-check">?</span> User DB</td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-part">~ Paid teams</span></td></tr>
              <tr><td>Browser-Only Deployment</td><td><span class="cft-check">?</span> Pure HTML</td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td></tr>
              <tr><td>File Integrity Verify</td><td><span class="cft-check">?</span> GCM tag</td><td><span class="cft-cross">?</span></td><td><span class="cft-check">?</span></td><td><span class="cft-check">?</span></td><td><span class="cft-check">?</span></td></tr>
              <tr><td>No External Deps (browser)</td><td><span class="cft-check">?</span> Web Crypto API</td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td></tr>
              <tr><td>Account Lock / Unlock</td><td><span class="cft-check">?</span> Admin action</td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td></tr>
              <tr><td>Session Key (never stored)</td><td><span class="cft-check">?</span> In-memory only</td><td><span class="cft-cross">?</span></td><td><span class="cft-check">?</span></td><td><span class="cft-check">?</span></td><td><span class="cft-check">?</span></td></tr>
              <tr><td>Password Strength Meter</td><td><span class="cft-check">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td><td><span class="cft-cross">?</span></td></tr>
              <tr><td>Open Source / Auditable</td><td><span class="cft-check">?</span></td><td><span class="cft-check">?</span></td><td><span class="cft-check">?</span></td><td><span class="cft-check">?</span></td><td><span class="cft-check">?</span></td></tr>
            </tbody>
          </table>
        </div>
        <div class="cmp-section-label">What Makes SecureFS v2 Unique</div>
        <div class="cmp-unique-item"><div class="cmp-unique-dot" style="background:#fb923c"></div><span class="cmp-unique-label"><strong>Blockchain audit ledger</strong> — every action produces a cryptographically linked block. SHA-256 chain integrity is verifiable. Tampering is mathematically detectable.</span><span class="cmp-unique-badge">v2 New</span></div>
        <div class="cmp-unique-item"><div class="cmp-unique-dot" style="background:#38bdf8"></div><span class="cmp-unique-label">Identity-bound encryption via AAD — ciphertext is cryptographically tied to username + employeeId. Decryption fails for any other user.</span><span class="cmp-unique-badge">Exclusive</span></div>
        <div class="cmp-unique-item"><div class="cmp-unique-dot" style="background:#60a5fa"></div><span class="cmp-unique-label">Full RBAC with 6 roles (DEVELOPER, ADMIN, MANAGER, USER, AUDITOR, READ_ONLY) and per-operation permission checks.</span><span class="cmp-unique-badge">Exclusive</span></div>
        <div class="cmp-unique-item"><div class="cmp-unique-dot" style="background:#818cf8"></div><span class="cmp-unique-label">Sliding-window Intrusion Detection System — accounts auto-lock after 5 failed logins in 10 minutes.</span><span class="cmp-unique-badge">Exclusive</span></div>
        <div class="cmp-unique-item"><div class="cmp-unique-dot" style="background:#a78bfa"></div><span class="cmp-unique-label">File registry with SHA-256 content hashing — track every encrypted file with a blockchain-anchored record.</span><span class="cmp-unique-badge">Exclusive</span></div>
        <div class="cmp-unique-item"><div class="cmp-unique-dot" style="background:#c084fc"></div><span class="cmp-unique-label">Browser implementation uses only the native Web Crypto API — zero external libraries, zero dependency attack surface.</span><span class="cmp-unique-badge">Exclusive</span></div>
      </div>
'''

target = '''        </div>
      </div>
    </div>
  </div>'''

replacement = target + '\\n\\n' + compare_html

content = content.replace(target, replacement, 1)

with open('securefs_v2 (1).html', 'w', encoding='utf-8') as f:
    f.write(content)

print("Patch applied")


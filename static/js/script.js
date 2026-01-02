/* ===============================
   TRUSTIFY — ANALYSIS ENGINE
   =============================== */

const API_ENDPOINT = "/api/analyze";

const checkBtn = document.getElementById("checkBtn");
const resultCard = document.getElementById("resultCard");

const statusIcon = document.getElementById("statusIcon");
const statusText = document.getElementById("statusText");
const progressBar = document.getElementById("progressBar");
const riskValue = document.getElementById("riskValue");

const aiAnalysis = document.getElementById("aiAnalysis");
const featureList = document.getElementById("featureList");
const resultPill = document.getElementById("resultPill");
const statusSubtext = document.getElementById("statusSubtext");

const domainVisuals = document.getElementById("domainVisuals");
const securityVisuals = document.getElementById("securityVisuals");
const structureVisuals = document.getElementById("structureVisuals");

let currentAnalysisData = null;

/* ===============================
   EXAMPLE BUTTON HANDLING
   =============================== */

const exampleBtns = document.querySelectorAll(".example-btn");
exampleBtns.forEach(btn => {
    btn.addEventListener("click", (e) => {
        const url = e.currentTarget.dataset.url;
        document.getElementById("urlInput").value = url;
        analyzeAndShow(url);
    });
});

/* ===============================
   MAIN ANALYZE BUTTON
   =============================== */

checkBtn.addEventListener("click", () => {
    const url = document.getElementById("urlInput").value.trim();
    if (!url) {
        alert("Please enter a URL");
        return;
    }
    analyzeAndShow(url);
});

/* ===============================
   EXPORT PDF
   =============================== */
const exportBtn = document.getElementById("exportBtn");

if (exportBtn) {
    exportBtn.addEventListener("click", () => {
        if (!currentAnalysisData) {
            alert("Please analyze a URL first.");
            return;
        }

        const originalText = exportBtn.innerText;
        exportBtn.innerText = "Generating...";
        exportBtn.disabled = true;

        fetch("/api/export-pdf", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(currentAnalysisData)
        })
        .then(resp => {
            if (!resp.ok) throw new Error("Export failed");
            return resp.blob();
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "Trustify_Report.pdf";
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        })
        .catch(err => {
            console.error(err);
            alert("Failed to generate PDF.");
        })
        .finally(() => {
            exportBtn.innerText = originalText;
            exportBtn.disabled = false;
        });
    });
}

/* ===============================
   ANALYSIS + UI RENDER
   =============================== */

function analyzeAndShow(raw) {
    currentAnalysisData = { url: raw };
    resultCard.classList.remove("hidden");

    domainVisuals.innerHTML = "";
    securityVisuals.innerHTML = "";
    structureVisuals.innerHTML = "";
    aiAnalysis.innerHTML = "";
    featureList.innerHTML = "";

    setStatusLoading();

    fetch(API_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: raw })
    })
        .then(async (resp) => {
            if (!resp.ok) {
                const msg = await resp.text();
                throw new Error(msg || "API error");
            }
            return resp.json();
        })
        .then((data) => renderServerResult(data))
        .catch((err) => {
            console.error("API analyze failed, using local heuristic", err);
            const fallback = analyzeURL(raw);
            renderHeuristic(fallback);
        });
}

/* ===============================
   HEURISTIC URL ANALYZER
   =============================== */

function analyzeURL(raw) {
    let url = raw;

    if (!/^[a-zA-Z]+:\/\//.test(url)) {
        url = "https://" + url;
    }

    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        return {
            score: 0,
            domainNotes: ["Invalid URL format"],
            securityNotes: [],
            contentNotes: []
        };
    }

    const host = parsed.hostname.toLowerCase();
    const path = parsed.pathname + parsed.search;

    const notesDomain = [];
    const notesSecurity = [];
    const notesContent = [];

    let risk = 0;

    /* ---- SSL CHECK ---- */
    if (parsed.protocol !== "https:") {
        risk += 22;
        notesSecurity.push("No HTTPS detected — missing TLS (increases risk).");
    } else {
        notesSecurity.push("HTTPS present (TLS detected).");
    }

    /* ---- IP ADDRESS HOST ---- */
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        risk += 30;
        notesDomain.push("Raw IP address used instead of domain (often suspicious).");
    }

    /* ---- DOMAIN LENGTH & HYPHENS ---- */
    if (host.length > 25) {
        risk += 8;
        notesDomain.push("Long hostname (>25 characters) may indicate obfuscation.");
    }

    const hyphens = (host.match(/-/g) || []).length;
    if (hyphens >= 2) {
        risk += 6;
        notesDomain.push("Multiple hyphens in hostname (common in typosquatting).");
    }

    /* ---- SUSPICIOUS TLDS ---- */
    const suspiciousTLDs = [".tk", ".ml", ".cf", ".ga", ".zip", ".review", "xn--"];
    suspiciousTLDs.forEach(tld => {
        if (host.includes(tld)) {
            risk += 10;
            notesDomain.push("Unusual or suspicious TLD / punycode detected.");
        }
    });

    /* ---- BRAND IMPERSONATION ---- */
    const knownBrands = [
        "google","paypal","amazon","microsoft",
        "apple","facebook","github","netflix","bank"
    ];

    let brandFlag = false;

    for (const brand of knownBrands) {
        if (host === brand + ".com") {
            notesDomain.push(`Exact brand domain detected: ${brand}.`);
            break;
        }

        if (host.includes(brand) && host !== brand + ".com") {
            const dist = levenshtein(
                host.replace(/[^a-z]/g, ""),
                brand
            );

            if (dist <= 2) {
                risk += 28;
                brandFlag = true;
                notesDomain.push(
                    `Possible impersonation of "${brand}" detected (typo variation).`
                );
                break;
            } else {
                notesDomain.push(
                    `Contains known brand keyword "${brand}" — verify legitimacy.`
                );
            }
        }
    }

    /* ---- SUSPICIOUS PATHS ---- */
    if (/login|signin|verify|secure|update|account/.test(path.toLowerCase())) {
        risk += brandFlag ? 10 : 6;
        notesContent.push(
            "Login-related path detected — commonly used in phishing pages."
        );
    }

    /* ---- UNICODE / HOMOGRAPH ---- */
    if (/xn--/.test(host) || /[^\x00-\x7F]/.test(host)) {
        risk += 20;
        notesDomain.push(
            "Non-ASCII / punycode characters detected (homograph attack risk)."
        );
    }

    /* ---- VERY SHORT DOMAIN ---- */
    if (host.length <= 3 && !host.includes("co")) {
        risk += 6;
        notesDomain.push("Very short domain — possible throwaway domain.");
    }

    /* ---- CONTENT PLACEHOLDER ---- */
    notesContent.push(
        "Content analysis not performed (requires backend crawling)."
    );

    const score = Math.max(0, Math.min(100, Math.round(100 - risk)));

    const domainNotes = notesDomain.length
        ? notesDomain
        : ["No immediate domain issues detected."];

    const securityNotes = notesSecurity.length
        ? notesSecurity
        : ["No immediate security issues detected."];

    const contentNotes = notesContent.length
        ? notesContent
        : ["No content anomalies detected."];

    if (score < 55) {
        contentNotes.unshift(
            "Classification: Suspicious — avoid entering credentials."
        );
    } else {
        contentNotes.unshift(
            "Classification: Likely Legitimate — remain cautious."
        );
    }

    return { score, domainNotes, securityNotes, contentNotes };
}

/* ===============================
   RENDER HELPERS (SERVER + FALLBACK)
   =============================== */

function renderServerResult(data) {
    // Clear containers to prevent duplicates
    domainVisuals.innerHTML = "";
    securityVisuals.innerHTML = "";
    structureVisuals.innerHTML = "";
    featureList.innerHTML = "";
    aiAnalysis.innerHTML = "";

    const riskScore = Math.round(Number(data.risk_score || 0));
    const score = 100 - riskScore;
    
    const label = data.risk_label || "";
    const result = data.result || "Unknown";
    const heuristic = Array.isArray(data.heuristic_reasons) ? data.heuristic_reasons : [];
    const features = data.url_features || {};

    // Update global data for PDF export
    if (currentAnalysisData) {
        currentAnalysisData = { 
            ...currentAnalysisData, 
            risk_score: score, 
            risk_label: label, 
            ai_summary: data.ai_suggestion 
        };
    }

    setStatus(score, result, label);

    // 1. Domain Analysis
    const uniqueNotes = Array.from(new Set(heuristic.map(n => n.trim()).filter(Boolean)));
    if (uniqueNotes.length > 0) {
        uniqueNotes.forEach(note => addVisualItem(domainVisuals, note, "danger"));
    } else {
        addVisualItem(domainVisuals, "No obvious typosquatting detected.", "success");
        addVisualItem(domainVisuals, "Domain syntax looks valid.", "success");
    }

    // Domain Age
    if (data.domain_age !== null && data.domain_age !== undefined) {
        const ageMsg = `Domain Age: ${data.domain_age} days`;
        const type = data.domain_age < 30 ? "danger" : "success";
        addVisualItem(domainVisuals, ageMsg, type);
    } else {
         addVisualItem(domainVisuals, "Domain age data unavailable.", "warning");
    }

    // Recent Scans
    if (data.recent_scans) {
        renderRecentScans(data.recent_scans);
    }

    // 2. Security Signals
    if (features.https) {
        addVisualItem(securityVisuals, "HTTPS Secured (TLS detected)", "success");
        addVisualItem(securityVisuals, "Valid SSL Certificate structure.", "success");
    } else {
        addVisualItem(securityVisuals, "No HTTPS detected (Not Secure)", "danger");
    }
    
    if (features.digit_count > 5) {
        addVisualItem(securityVisuals, "High digit count in URL (Suspicious)", "warning");
    } else {
        addVisualItem(securityVisuals, "Low digit count (Normal)", "success");
    }

    // 3. URL Structure (Progress Bars)
    addProgressItem(structureVisuals, "URL Length", features.url_length, 75, "Length of the full URL");
    addProgressItem(structureVisuals, "Domain Length", features.domain_length, 30, "Length of the domain part");
    addProgressItem(structureVisuals, "Subdomains", features.subdomain_count, 3, "Number of subdomains");

    renderFeatureList(features);

    const ai = (data.ai_suggestion || "No AI explanation available.")
        .split(/\n+/)
        .map(t => t.trim())
        .filter(Boolean);
    renderAI(ai);

    progressBar.style.width = score + "%";
    riskValue.innerText = `${score} / 100 (${label})`;
    resultPill.innerText = result;
    resultPill.classList.remove("safe", "danger");
    resultPill.classList.add(score < 55 ? "danger" : "safe");
    statusSubtext.innerText = "Backend model + OpenAI reasoning";
}

function renderHeuristic(res) {
    // Clear containers
    domainVisuals.innerHTML = "";
    securityVisuals.innerHTML = "";
    structureVisuals.innerHTML = "";
    featureList.innerHTML = "";
    aiAnalysis.innerHTML = "";

    setStatus(res.score, res.score < 55 ? "Suspicious" : "Likely Legitimate", "Heuristic");

    // 1. Domain
    const uniqueDomain = Array.from(new Set(res.domainNotes.map(n => n.trim()).filter(Boolean)));
    if (uniqueDomain.length > 0) {
        uniqueDomain.forEach(note => addVisualItem(domainVisuals, note, "danger"));
    } else {
        addVisualItem(domainVisuals, "No obvious typosquatting detected.", "success");
        addVisualItem(domainVisuals, "Domain syntax looks valid.", "success");
    }

    // 2. Security
    res.securityNotes.forEach(note => {
        const type = note.includes("No HTTPS") ? "danger" : "success";
        addVisualItem(securityVisuals, note, type);
    });
    if (res.securityNotes.some(n => n.includes("HTTPS"))) {
         addVisualItem(securityVisuals, "Standard SSL port (443) inferred.", "success");
    }

    // 3. Structure / Content
    res.contentNotes.forEach(note => addVisualItem(structureVisuals, note, "warning"));
    
    // Add dummy progress bars for heuristic mode if we don't have exact features
    // Or just leave it with content notes.

    progressBar.style.width = res.score + "%";
    riskValue.innerText = res.score + " / 100 (Heuristic)";
    resultPill.innerText = res.score < 55 ? "Suspicious" : "Likely Legitimate";
    resultPill.classList.remove("safe", "danger");
    resultPill.classList.add(res.score < 55 ? "danger" : "safe");
    statusSubtext.innerText = "Local heuristic fallback";
}

function addVisualItem(container, text, type) {
    const div = document.createElement("div");
    div.className = `visual-item ${type}`;
    div.innerHTML = `<span>${text}</span>`;
    container.appendChild(div);
}

function addProgressItem(container, label, value, max, tooltip) {
    const pct = Math.min((value / max) * 100, 100);
    let colorClass = "low";
    if (pct > 80) colorClass = "high";
    else if (pct > 50) colorClass = "med";

    const div = document.createElement("div");
    div.className = "progress-item";
    div.innerHTML = `
        <div class="progress-header">
            <span>${label}</span>
            <span>${value}</span>
        </div>
        <div class="progress-track" title="${tooltip}">
            <div class="progress-fill ${colorClass}" style="width: ${pct}%"></div>
        </div>
    `;
    container.appendChild(div);
}

function setStatus(score, resultText, labelText) {
    const suspicious = resultText.toLowerCase().includes("suspicious") || score < 55;
    if (suspicious) {
        statusIcon.innerText = "⚠️";
        statusText.innerText = `${resultText} — take caution (${labelText})`;
        statusText.style.color = "#ef4444";
        progressBar.style.background = "#ef4444";
    } else {
        statusIcon.innerText = "✅";
        statusText.innerText = `${resultText} (${labelText})`;
        statusText.style.color = "#22c55e";
        progressBar.style.background = "linear-gradient(90deg,#38bdf8,#22c55e)";
    }
}

function setStatusLoading() {
    statusIcon.innerText = "⏳";
    statusText.innerText = "Analyzing...";
    statusText.style.color = "#0f172a";
    progressBar.style.background = "#0ea5e9";
    progressBar.style.width = "35%";
    resultPill.innerText = "Running checks";
    statusSubtext.innerText = "Calling backend and AI";
}

/* ===============================
   HELPERS
   =============================== */

function add(list, text) {
    const li = document.createElement("li");
    li.innerText = text;
    list.appendChild(li);
}

function addIfAbsent(list, text) {
    const exists = Array.from(list.querySelectorAll("li")).some(li => li.innerText === text);
    if (!exists) add(list, text);
}

function renderAI(lines) {
    aiAnalysis.innerHTML = "";
    const target = lines.length ? lines : ["No AI explanation available."];
    target.forEach(line => {
        const p = document.createElement("p");
        p.innerText = line;
        aiAnalysis.appendChild(p);
    });
}

function renderFeatureList(features) {
    featureList.innerHTML = "";
    if (!Object.keys(features).length) {
        featureList.innerHTML = "<div class='feature-item'><span class='feature-value'>No Data</span></div>";
        return;
    }

    const entries = [
        ["HTTPS", features.https ? "Yes" : "No"],
        ["Subdomains", features.subdomain_count],
        ["Digits", features.digit_count],
        ["Length", features.url_length],
        ["Path Len", features.path_length],
        ["Query Len", features.query_length]
    ];

    entries.forEach(([label, value]) => {
        const div = document.createElement("div");
        div.className = "feature-item";
        
        const lbl = document.createElement("span");
        lbl.className = "feature-label";
        lbl.innerText = label;
        
        const val = document.createElement("span");
        val.className = "feature-value";
        val.innerText = value;
        
        div.appendChild(lbl);
        div.appendChild(val);
        featureList.appendChild(div);
    });
}

function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, () =>
        new Array(n + 1).fill(0)
    );

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;
            dp[i][j] = Math.min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            );
        }
    }
    return dp[m][n];
}

/* ===============================
   LOGIN MODAL INTEGRATION
   =============================== */

(() => {
    const openBtn = document.getElementById("openLoginBtn");
    const modal = document.getElementById("loginModal");
    const backdrop = document.getElementById("loginBackdrop");
    const closeBtn = document.getElementById("loginClose");

    const signUpBtn = document.getElementById("signUp");
    const signInBtn = document.getElementById("signIn");
    const loginContainer = document.getElementById("loginContainer");

    function openModal() {
        modal.classList.remove("hidden");
        modal.setAttribute("aria-hidden", "false");
        loginContainer.classList.remove("right-panel-active");
    }

    function closeModal() {
        modal.classList.add("hidden");
        modal.setAttribute("aria-hidden", "true");
    }

    openBtn?.addEventListener("click", openModal);
    closeBtn?.addEventListener("click", closeModal);
    backdrop?.addEventListener("click", closeModal);

    signUpBtn?.addEventListener("click", () => {
        loginContainer.classList.add("right-panel-active");
    });

    signInBtn?.addEventListener("click", () => {
        loginContainer.classList.remove("right-panel-active");
    });

})();

/* ===============================
   CHATBOT LOGIC
   =============================== */
(() => {
    const toggleBtn = document.getElementById("chatToggleBtn");
    const closeBtn = document.getElementById("chatCloseBtn");
    const chatWindow = document.getElementById("chatWindow");
    const input = document.getElementById("chatInput");
    const sendBtn = document.getElementById("chatSendBtn");
    const messages = document.getElementById("chatMessages");

    if (!toggleBtn || !chatWindow) return;

    // Toggle Window
    toggleBtn.addEventListener("click", () => {
        chatWindow.classList.toggle("hidden");
        if (!chatWindow.classList.contains("hidden")) {
            input.focus();
        }
    });

    closeBtn.addEventListener("click", () => {
        chatWindow.classList.add("hidden");
    });

    // Send Message
    function sendMessage() {
        const text = input.value.trim();
        if (!text) return;

        appendMessage(text, "user");
        input.value = "";

        // Show typing indicator (optional, or just wait)
        const loadingId = appendMessage("Thinking...", "bot", true);

        fetch("/api/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: text })
        })
        .then(res => res.json())
        .then(data => {
            removeMessage(loadingId);
            appendMessage(data.reply || "Sorry, I couldn't understand that.", "bot");
        })
        .catch(() => {
            removeMessage(loadingId);
            appendMessage("Network error. Please try again.", "bot");
        });
    }

    sendBtn.addEventListener("click", sendMessage);
    input.addEventListener("keypress", (e) => {
        if (e.key === "Enter") sendMessage();
    });

    function appendMessage(text, sender, isTemp = false) {
        const div = document.createElement("div");
        div.className = `message ${sender}`;
        div.innerText = text;

        if (isTemp) div.id = "tempMsg_" + Date.now();
        messages.appendChild(div);
        messages.scrollTop = messages.scrollHeight;

        // Auto-speak for bot
        if (sender === "bot" && !isTemp) {
            if ('speechSynthesis' in window) {
                window.speechSynthesis.cancel();
                const u = new SpeechSynthesisUtterance(text);
                u.lang = 'en-US';
                window.speechSynthesis.speak(u);
            }
        }

        return div.id;
    }

    function removeMessage(id) {
        if (!id) return;
        const el = document.getElementById(id);
        if (el) el.remove();
    }
})();
/* ===============================
   RECENT SCANS
   =============================== */
function renderRecentScans(list) {
    const section = document.getElementById('recentScansSection');
    const container = document.getElementById('recentList');
    if (!list || list.length === 0) {
        if(section) section.style.display = 'none';
        return;
    }
    
    if(section) section.style.display = 'block';
    if(container) {
        container.innerHTML = '';
        list.forEach(item => {
            const div = document.createElement('div');
            div.className = 'recent-item';
            div.style.cssText = 'background: rgba(255,255,255,0.05); padding: 10px; margin-bottom: 8px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center;';
            
            const isSuspicious = item.result.toLowerCase().includes('suspicious');
            const color = isSuspicious ? '#ef4444' : '#22c55e';
            
            div.innerHTML = `
                <div style='overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 70%;'>
                    <span style='color: #94a3b8; font-size: 0.85rem;'>${item.time}</span>
                    <span style='margin-left: 10px; font-weight: 500;'>${item.url}</span>
                </div>
                <div style='color: ${color}; font-weight: 600; font-size: 0.9rem;'>
                    ${item.score}/100
                </div>
            `;
            container.appendChild(div);
        });
    }
}

// Load recent on start
fetch('/api/recent')
    .then(r => r.json())
    .then(data => renderRecentScans(data))
    .catch(() => {});


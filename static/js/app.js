/**
 * VibeCheck — Frontend Logic
 * Evidence-based scoring: every point is backed by a verifiable finding.
 */

document.addEventListener("DOMContentLoaded", () => {
    // ── Elements ────────────────────────────────────────────────────
    const urlForm = document.getElementById("urlForm");
    const urlInput = document.getElementById("urlInput");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const btnText = analyzeBtn.querySelector(".btn-text");
    const btnLoader = analyzeBtn.querySelector(".btn-loader");

    const heroSection = document.getElementById("hero");
    const loadingSection = document.getElementById("loadingSection");
    const resultsSection = document.getElementById("resultsSection");
    const errorSection = document.getElementById("errorSection");

    const loadingSteps = document.getElementById("loadingSteps").children;
    const scoreNumber = document.getElementById("scoreNumber");
    const gaugeFill = document.getElementById("gaugeFill");
    const verdictEmoji = document.getElementById("verdictEmoji");
    const verdictText = document.getElementById("verdictText");
    const verdictUrl = document.getElementById("verdictUrl");
    const scanStats = document.getElementById("scanStats");
    const evidenceSummary = document.getElementById("evidenceSummary");
    const categoriesGrid = document.getElementById("categoriesGrid");
    const errorMessage = document.getElementById("errorMessage");

    const tryAnotherBtn = document.getElementById("tryAnotherBtn");
    const errorRetryBtn = document.getElementById("errorRetryBtn");

    // ── Background particles ────────────────────────────────────────
    createParticles();
    addGaugeGradient();

    // ── Event listeners ─────────────────────────────────────────────
    urlForm.addEventListener("submit", handleSubmit);
    tryAnotherBtn.addEventListener("click", resetToInput);
    errorRetryBtn.addEventListener("click", resetToInput);

    // ── Form submit ─────────────────────────────────────────────────
    async function handleSubmit(e) {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) return;

        showSection("loading");
        setButtonLoading(true);
        animateLoadingSteps();

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url }),
            });

            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Unknown error occurred");
            }

            await sleep(800);
            showSection("results");
            renderResults(data);
        } catch (err) {
            showSection("error");
            errorMessage.textContent = err.message;
        } finally {
            setButtonLoading(false);
        }
    }

    function showSection(name) {
        heroSection.style.display = name === "hero" ? "" : "none";
        loadingSection.style.display = name === "loading" ? "" : "none";
        resultsSection.style.display = name === "results" ? "" : "none";
        errorSection.style.display = name === "error" ? "" : "none";
    }

    function resetToInput() {
        showSection("hero");
        urlInput.focus();
        urlInput.select();
    }

    function setButtonLoading(loading) {
        analyzeBtn.disabled = loading;
        btnText.style.display = loading ? "none" : "";
        btnLoader.style.display = loading ? "" : "none";
    }

    function animateLoadingSteps() {
        const steps = Array.from(loadingSteps);
        steps.forEach((s) => s.classList.remove("active", "done"));
        let i = 0;
        steps[0].classList.add("active");
        const interval = setInterval(() => {
            if (i < steps.length) {
                steps[i].classList.remove("active");
                steps[i].classList.add("done");
            }
            i++;
            if (i < steps.length) {
                steps[i].classList.add("active");
            } else {
                clearInterval(interval);
            }
        }, 600);
    }

    // ── Render results ──────────────────────────────────────────────
    function renderResults(data) {
        // Score
        animateCounter(scoreNumber, data.overall_score, 1500);
        const circumference = 2 * Math.PI * 85;
        const offset = circumference - (data.overall_score / 100) * circumference;
        gaugeFill.style.strokeDashoffset = offset;
        updateGaugeColor(data.overall_score);
        scoreNumber.style.color = getScoreColor(data.overall_score);

        // Verdict
        verdictEmoji.textContent = data.verdict_emoji;
        verdictText.textContent = data.verdict;
        verdictUrl.textContent = data.url;

        // Scan stats
        scanStats.innerHTML = `
            <span class="stat-chip">📄 ${data.pages_analyzed} page${data.pages_analyzed > 1 ? "s" : ""} analyzed</span>
            <span class="stat-chip">📦 ${data.assets_analyzed} asset${data.assets_analyzed > 1 ? "s" : ""} scanned</span>
        `;

        // ── Evidence Summary ────────────────────────────────────────
        renderEvidenceSummary(data.evidence_summary, data.overall_score);

        // ── Categories ──────────────────────────────────────────────
        categoriesGrid.innerHTML = "";
        const orderedCategories = [
            "ai_platforms", "ui_libraries", "frameworks", "content",
            "code_quality", "deployment", "design_patterns",
            "accessibility", "seo_quality",
        ];

        orderedCategories.forEach((key) => {
            const cat = data.categories[key];
            if (!cat) return;
            categoriesGrid.appendChild(createCategoryCard(cat));
        });

        requestAnimationFrame(() => {
            document.querySelectorAll(".category-progress-fill").forEach((bar) => {
                bar.style.width = bar.dataset.width;
            });
        });
    }

    // ── Evidence Summary ────────────────────────────────────────────
    function renderEvidenceSummary(summary, score) {
        if (!summary) {
            evidenceSummary.innerHTML = "";
            return;
        }

        const tiers = [
            { key: "definitive", icon: "🎯", color: "#ef4444", bgColor: "rgba(239,68,68,0.1)", borderColor: "rgba(239,68,68,0.3)" },
            { key: "strong", icon: "🔥", color: "#f97316", bgColor: "rgba(249,115,22,0.1)", borderColor: "rgba(249,115,22,0.3)" },
            { key: "moderate", icon: "📊", color: "#f59e0b", bgColor: "rgba(245,158,11,0.1)", borderColor: "rgba(245,158,11,0.3)" },
            { key: "weak", icon: "💨", color: "#6b7280", bgColor: "rgba(107,114,128,0.1)", borderColor: "rgba(107,114,128,0.3)" },
        ];

        let html = `
            <div class="evidence-header">
                <h3>📋 Evidence Breakdown</h3>
                <p class="evidence-subtitle">Score computed from ${Object.values(summary).reduce((a, b) => a + b.count, 0)} findings across 4 evidence tiers. Weak signals are capped to prevent score inflation.</p>
            </div>
            <div class="evidence-tiers">
        `;

        tiers.forEach(({ key, icon, color, bgColor, borderColor }) => {
            const tier = summary[key];
            if (!tier) return;
            const wasCapped = tier.raw_points > tier.capped_points;
            html += `
                <div class="evidence-tier-card" style="border-color: ${borderColor}; background: ${bgColor}">
                    <div class="tier-top">
                        <span class="tier-icon">${icon}</span>
                        <span class="tier-label" style="color: ${color}">${tier.label}</span>
                    </div>
                    <div class="tier-count">${tier.count}</div>
                    <div class="tier-detail">finding${tier.count !== 1 ? "s" : ""}</div>
                    <div class="tier-points" style="color: ${color}">
                        +${tier.capped_points} pts${wasCapped ? ` <span class="tier-capped">(capped from ${tier.raw_points})</span>` : ""}
                    </div>
                </div>
            `;
        });

        html += `</div>`;
        evidenceSummary.innerHTML = html;
    }

    // ── Category Card ───────────────────────────────────────────────
    function createCategoryCard(cat) {
        const card = document.createElement("div");
        card.className = "category-card";
        const scoreClass = getScoreClass(cat.score);
        const fillClass = "fill-" + scoreClass.replace("score-", "");

        card.innerHTML = `
            <div class="category-header">
                <div class="category-title">
                    <span class="category-icon">${cat.icon}</span>
                    ${cat.name}
                </div>
                <span class="category-score ${scoreClass}">${cat.score}</span>
            </div>
            <div class="category-progress">
                <div class="category-progress-fill ${fillClass}" data-width="${cat.score}%"></div>
            </div>
            <div class="findings-list">
                ${cat.findings.length === 0
                ? '<div class="no-findings">No signals detected</div>'
                : cat.findings
                    .map(
                        (f) => `
                        <div class="finding-item">
                            <span class="finding-badge tier-${f.tier}">${f.tier_label}</span>
                            <span class="finding-points">+${f.points}</span>
                            <span>${escapeHtml(f.description)}${f.evidence ? ` <span style="color:var(--text-muted)">(${escapeHtml(f.evidence)})</span>` : ""}${f.page ? ` <span style="color:var(--text-muted);font-size:0.72rem">on ${escapeHtml(f.page)}</span>` : ""}</span>
                        </div>
                    `
                    )
                    .join("")
            }
            </div>
        `;

        return card;
    }

    // ── Helpers ──────────────────────────────────────────────────────
    function getScoreClass(score) {
        if (score >= 75) return "score-critical";
        if (score >= 50) return "score-high";
        if (score >= 25) return "score-medium";
        return "score-low";
    }

    function getScoreColor(score) {
        if (score >= 75) return "var(--danger)";
        if (score >= 50) return "var(--orange)";
        if (score >= 25) return "var(--warning)";
        return "var(--success)";
    }

    function updateGaugeColor(score) {
        const g1 = document.getElementById("gaugeGradientStop1");
        const g2 = document.getElementById("gaugeGradientStop2");
        if (!g1 || !g2) return;
        if (score >= 75) {
            g1.setAttribute("stop-color", "#ef4444");
            g2.setAttribute("stop-color", "#f97316");
        } else if (score >= 50) {
            g1.setAttribute("stop-color", "#f97316");
            g2.setAttribute("stop-color", "#f59e0b");
        } else if (score >= 25) {
            g1.setAttribute("stop-color", "#f59e0b");
            g2.setAttribute("stop-color", "#eab308");
        } else {
            g1.setAttribute("stop-color", "#22c55e");
            g2.setAttribute("stop-color", "#4ade80");
        }
    }

    function animateCounter(element, target, duration) {
        const startTime = performance.now();
        function update(currentTime) {
            const progress = Math.min((currentTime - startTime) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            element.textContent = Math.round(target * eased);
            if (progress < 1) requestAnimationFrame(update);
        }
        requestAnimationFrame(update);
    }

    function escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }

    function sleep(ms) {
        return new Promise((r) => setTimeout(r, ms));
    }

    function createParticles() {
        const container = document.getElementById("bgParticles");
        for (let i = 0; i < 25; i++) {
            const p = document.createElement("div");
            p.className = "particle";
            const s = Math.random() * 4 + 2;
            p.style.width = `${s}px`;
            p.style.height = `${s}px`;
            p.style.left = `${Math.random() * 100}%`;
            p.style.animationDuration = `${Math.random() * 15 + 10}s`;
            p.style.animationDelay = `${Math.random() * 10}s`;
            container.appendChild(p);
        }
    }

    function addGaugeGradient() {
        const svg = document.querySelector(".gauge-svg");
        if (!svg) return;
        const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
        defs.innerHTML = `
            <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop id="gaugeGradientStop1" offset="0%" stop-color="#8b5cf6"/>
                <stop id="gaugeGradientStop2" offset="100%" stop-color="#6366f1"/>
            </linearGradient>
        `;
        svg.prepend(defs);
    }
});

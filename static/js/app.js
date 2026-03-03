/**
 * VibeCheck — Frontend Logic
 * Handles form submission, API calls, loading animation, and results rendering.
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
    const categoriesGrid = document.getElementById("categoriesGrid");
    const scanStats = document.getElementById("scanStats");
    const errorMessage = document.getElementById("errorMessage");

    const tryAnotherBtn = document.getElementById("tryAnotherBtn");
    const errorRetryBtn = document.getElementById("errorRetryBtn");

    // ── Background particles ────────────────────────────────────────
    createParticles();

    // ── Add SVG gradient definition for gauge ───────────────────────
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

            // Wait for loading animation to feel natural
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

    // ── Section visibility ──────────────────────────────────────────
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

    // ── Button state ────────────────────────────────────────────────
    function setButtonLoading(loading) {
        analyzeBtn.disabled = loading;
        btnText.style.display = loading ? "none" : "";
        btnLoader.style.display = loading ? "" : "none";
    }

    // ── Loading animation ───────────────────────────────────────────
    function animateLoadingSteps() {
        const steps = Array.from(loadingSteps);
        steps.forEach((s) => {
            s.classList.remove("active", "done");
        });

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
        // Animate score number
        animateCounter(scoreNumber, data.overall_score, 1500);

        // Animate gauge
        const circumference = 2 * Math.PI * 85; // ~534
        const offset = circumference - (data.overall_score / 100) * circumference;
        gaugeFill.style.strokeDashoffset = offset;

        // Update gradient colours based on score
        updateGaugeColor(data.overall_score);

        // Score number colour
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

        // Categories
        categoriesGrid.innerHTML = "";
        const orderedCategories = [
            "ai_platforms",
            "ui_libraries",
            "frameworks",
            "content",
            "code_style",
            "deployment",
            "design_patterns",
        ];

        orderedCategories.forEach((key) => {
            const cat = data.categories[key];
            if (!cat) return;
            categoriesGrid.appendChild(createCategoryCard(cat));
        });

        // Animate progress bars after render
        requestAnimationFrame(() => {
            document.querySelectorAll(".category-progress-fill").forEach((bar) => {
                bar.style.width = bar.dataset.width;
            });
        });
    }

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
                            <span class="finding-badge confidence-${f.confidence}">${f.confidence}</span>
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
        const grad = document.getElementById("gaugeGradientStop1");
        const grad2 = document.getElementById("gaugeGradientStop2");
        if (!grad || !grad2) return;

        if (score >= 75) {
            grad.setAttribute("stop-color", "#ef4444");
            grad2.setAttribute("stop-color", "#f97316");
        } else if (score >= 50) {
            grad.setAttribute("stop-color", "#f97316");
            grad2.setAttribute("stop-color", "#f59e0b");
        } else if (score >= 25) {
            grad.setAttribute("stop-color", "#f59e0b");
            grad2.setAttribute("stop-color", "#eab308");
        } else {
            grad.setAttribute("stop-color", "#22c55e");
            grad2.setAttribute("stop-color", "#4ade80");
        }
    }

    function animateCounter(element, target, duration) {
        const start = 0;
        const startTime = performance.now();

        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            // Ease out cubic
            const eased = 1 - Math.pow(1 - progress, 3);
            const current = Math.round(start + (target - start) * eased);

            element.textContent = current;

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        }

        requestAnimationFrame(update);
    }

    function escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }

    function sleep(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    // ── Background particles ────────────────────────────────────────
    function createParticles() {
        const container = document.getElementById("bgParticles");
        const count = 25;

        for (let i = 0; i < count; i++) {
            const particle = document.createElement("div");
            particle.className = "particle";
            const size = Math.random() * 4 + 2;
            particle.style.width = `${size}px`;
            particle.style.height = `${size}px`;
            particle.style.left = `${Math.random() * 100}%`;
            particle.style.animationDuration = `${Math.random() * 15 + 10}s`;
            particle.style.animationDelay = `${Math.random() * 10}s`;
            container.appendChild(particle);
        }
    }

    // ── SVG gradient for gauge ──────────────────────────────────────
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

document.addEventListener('DOMContentLoaded', () => {
  // Initialize Lucide icons
  if (window.lucide) {
    lucide.createIcons();
  }

  const urlForm = document.getElementById('urlForm');
  const urlInput = document.getElementById('urlInput');
  const clearBtn = document.getElementById('clearBtn');
  const submitBtn = document.getElementById('submitBtn');
  const loadingState = document.getElementById('loadingState');
  const errorState = document.getElementById('errorState');
  const errorMessage = document.getElementById('errorMessage');
  const resultsSection = document.getElementById('resultsSection');

  const verdictCard = document.getElementById('verdictCard');
  const verdictBadge = document.getElementById('verdictBadge');
  const verdictText = document.getElementById('verdictText');
  const verdictIcon = document.getElementById('verdictIcon');
  const verdictHeadline = document.getElementById('verdictHeadline');
  const verdictDesc = document.getElementById('verdictDesc');
  const displayUrl = document.getElementById('displayUrl');
  const confidenceText = document.getElementById('confidenceText');

  const gaugeFill = document.getElementById('gaugeFill');
  const gaugeScore = document.getElementById('gaugeScore');
  const gaugeLabel = document.getElementById('gaugeLabel');

  const anatScheme = document.getElementById('anatScheme');
  const anatHost = document.getElementById('anatHost');
  const anatDomain = document.getElementById('anatDomain');
  const anatSubdomain = document.getElementById('anatSubdomain');
  const anatTld = document.getElementById('anatTld');
  const anatPath = document.getElementById('anatPath');

  const goodReasonsList = document.getElementById('goodReasonsList');
  const fakeReasonsList = document.getElementById('fakeReasonsList');
  const goodCountBadge = document.getElementById('goodCountBadge');
  const fakeCountBadge = document.getElementById('fakeCountBadge');

  const recommendationsList = document.getElementById('recommendationsList');
  const featureToggleBtn = document.getElementById('featureToggleBtn');
  const featureToggleIcon = document.getElementById('featureToggleIcon');
  const featureGridContainer = document.getElementById('featureGridContainer');
  const featureGrid = document.getElementById('featureGrid');

  // Input clear button toggle
  urlInput.addEventListener('input', () => {
    if (urlInput.value.trim().length > 0) {
      clearBtn.classList.remove('hidden');
    } else {
      clearBtn.classList.add('hidden');
    }
  });

  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    clearBtn.classList.add('hidden');
    urlInput.focus();
  });

  // Sample Chips click listener
  document.querySelectorAll('.sample-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const sampleUrl = chip.getAttribute('data-url');
      if (sampleUrl) {
        urlInput.value = sampleUrl;
        clearBtn.classList.remove('hidden');
        triggerAnalysis(sampleUrl);
      }
    });
  });

  // Form submission
  urlForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;
    triggerAnalysis(url);
  });

  // Feature inspector accordion toggle
  featureToggleBtn.addEventListener('click', () => {
    const isHidden = featureGridContainer.classList.contains('hidden');
    if (isHidden) {
      featureGridContainer.classList.remove('hidden');
      featureToggleIcon.style.transform = 'rotate(180deg)';
    } else {
      featureGridContainer.classList.add('hidden');
      featureToggleIcon.style.transform = 'rotate(0deg)';
    }
  });

  async function triggerAnalysis(url) {
    // Reset views
    errorState.classList.add('hidden');
    resultsSection.classList.add('hidden');
    loadingState.classList.remove('hidden');
    submitBtn.disabled = true;
    submitBtn.classList.add('opacity-70', 'cursor-not-allowed');

    // Scroll to loading area smoothly
    loadingState.scrollIntoView({ behavior: 'smooth', block: 'center' });

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: url })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Failed to analyze URL');
      }

      renderResults(data);

    } catch (err) {
      console.error(err);
      errorMessage.textContent = err.message || 'An error occurred during analysis.';
      errorState.classList.remove('hidden');
    } finally {
      loadingState.classList.add('hidden');
      submitBtn.disabled = false;
      submitBtn.classList.remove('opacity-70', 'cursor-not-allowed');
    }
  }

  function renderResults(data) {
    displayUrl.textContent = data.url;
    confidenceText.textContent = `${data.confidence}%`;

    // 1. Verdict card and glow
    verdictCard.classList.remove('glass-panel-glow-green', 'glass-panel-glow-red', 'glass-panel-glow-amber');
    verdictBadge.classList.remove('badge-success', 'badge-danger', 'badge-warning');

    let gaugeColor = '#10b981';
    let iconName = 'shield-check';

    if (data.verdict === 'FAKE / PHISHING') {
      verdictCard.classList.add('glass-panel-glow-red');
      verdictBadge.classList.add('badge-danger');
      verdictText.textContent = 'FAKE / PHISHING PORTAL';
      iconName = 'alert-octagon';
      verdictHeadline.textContent = '🚨 Malicious Fake Login Detected!';
      verdictHeadline.className = 'text-2xl sm:text-3xl font-extrabold text-rose-400 glow-text-red';
      gaugeColor = '#f43f5e';
      gaugeLabel.textContent = 'Threat Level: Critical Phish';
      gaugeLabel.className = 'text-xs font-semibold tracking-wide uppercase mt-2 text-rose-400';
    } else if (data.verdict === 'SUSPICIOUS') {
      verdictCard.classList.add('glass-panel-glow-amber');
      verdictBadge.classList.add('badge-warning');
      verdictText.textContent = 'SUSPICIOUS / HIGH CAUTION';
      iconName = 'alert-triangle';
      verdictHeadline.textContent = '⚠️ Suspicious Website Characteristics';
      verdictHeadline.className = 'text-2xl sm:text-3xl font-extrabold text-amber-400';
      gaugeColor = '#f59e0b';
      gaugeLabel.textContent = 'Threat Level: Medium Caution';
      gaugeLabel.className = 'text-xs font-semibold tracking-wide uppercase mt-2 text-amber-400';
    } else {
      verdictCard.classList.add('glass-panel-glow-green');
      verdictBadge.classList.add('badge-success');
      verdictText.textContent = 'LEGITIMATE / GOOD WEBSITE';
      iconName = 'shield-check';
      verdictHeadline.textContent = '🛡️ Verified Legitimate & Safe Website';
      verdictHeadline.className = 'text-2xl sm:text-3xl font-extrabold text-emerald-400 glow-text-green';
      gaugeColor = '#10b981';
      gaugeLabel.textContent = 'Threat Level: Safe & Trusted';
      gaugeLabel.className = 'text-xs font-semibold tracking-wide uppercase mt-2 text-emerald-400';
    }

    verdictDesc.textContent = data.status_message;

    // 2. Animated Gauge
    const circumference = 314.159; // 2 * PI * 50
    const risk = Math.min(Math.max(data.risk_score, 0), 100);
    const offset = circumference - (risk / 100) * circumference;

    gaugeFill.style.stroke = gaugeColor;
    gaugeFill.style.strokeDasharray = `${circumference}`;
    gaugeFill.style.strokeDashoffset = `${offset}`;
    gaugeScore.textContent = `${risk}%`;

    // 3. Anatomy breakdown
    const comp = data.components || {};
    anatScheme.textContent = comp.scheme || 'N/A';
    anatHost.textContent = comp.netloc || 'N/A';
    anatDomain.textContent = comp.registered_domain || 'N/A';
    anatSubdomain.textContent = comp.subdomain || '(none)';
    anatTld.textContent = comp.tld ? `.${comp.tld}` : '(none)';
    anatPath.textContent = comp.path || '/';

    // 4. Why is this Good? (reasons_good)
    goodCountBadge.textContent = `${data.reasons_good.length} Factors`;
    if (data.reasons_good && data.reasons_good.length > 0) {
      goodReasonsList.innerHTML = data.reasons_good.map(r => `
        <div class="p-3.5 rounded-xl bg-slate-900/90 border border-emerald-800/40 flex items-start space-x-3 transition hover:border-emerald-600/60">
          <div class="h-6 w-6 rounded-full bg-emerald-950 text-emerald-400 flex items-center justify-center shrink-0 mt-0.5 border border-emerald-800/60">
            <i data-lucide="${r.icon || 'check-circle'}" class="w-3.5 h-3.5"></i>
          </div>
          <div>
            <h4 class="text-sm font-bold text-emerald-300">${escapeHtml(r.title)}</h4>
            <p class="text-xs text-slate-400 mt-0.5 leading-relaxed">${escapeHtml(r.desc)}</p>
          </div>
        </div>
      `).join('');
    } else {
      goodReasonsList.innerHTML = `
        <div class="p-4 rounded-xl bg-slate-900/50 border border-slate-800 text-center text-xs text-slate-500 italic">
          No official safety verification factors confirmed for this domain.
        </div>
      `;
    }

    // 5. Why is this Fake? (reasons_fake)
    fakeCountBadge.textContent = `${data.reasons_fake.length} Red Flags`;
    if (data.reasons_fake && data.reasons_fake.length > 0) {
      fakeReasonsList.innerHTML = data.reasons_fake.map(r => {
        let badgeClass = 'bg-slate-800 text-slate-300';
        if (r.severity === 'critical') badgeClass = 'bg-rose-950 text-rose-300 border border-rose-800';
        else if (r.severity === 'high') badgeClass = 'bg-amber-950 text-amber-300 border border-amber-800';
        else if (r.severity === 'medium') badgeClass = 'bg-yellow-950 text-yellow-300 border border-yellow-800';

        return `
          <div class="p-3.5 rounded-xl bg-slate-900/90 border border-rose-800/40 flex items-start space-x-3 transition hover:border-rose-600/60">
            <div class="h-6 w-6 rounded-full bg-rose-950 text-rose-400 flex items-center justify-center shrink-0 mt-0.5 border border-rose-800/60">
              <i data-lucide="${r.icon || 'alert-triangle'}" class="w-3.5 h-3.5"></i>
            </div>
            <div class="flex-1">
              <div class="flex items-center justify-between">
                <h4 class="text-sm font-bold text-rose-300">${escapeHtml(r.title)}</h4>
                <span class="text-[10px] uppercase font-mono px-2 py-0.5 rounded ${badgeClass}">${r.severity || 'risk'}</span>
              </div>
              <p class="text-xs text-slate-400 mt-1 leading-relaxed">${escapeHtml(r.desc)}</p>
            </div>
          </div>
        `;
      }).join('');
    } else {
      fakeReasonsList.innerHTML = `
        <div class="p-4 rounded-xl bg-slate-900/50 border border-slate-800 text-center text-xs text-emerald-400 flex items-center justify-center space-x-2">
          <i data-lucide="check-check" class="w-4 h-4"></i>
          <span>Zero phishing anomalies or deceptive tokens detected.</span>
        </div>
      `;
    }

    // 6. Security Recommendations
    if (data.recommendations && data.recommendations.length > 0) {
      recommendationsList.innerHTML = data.recommendations.map(rec => `
        <li class="flex items-start space-x-2.5 p-2 rounded-lg bg-slate-950/40 border border-slate-800/60">
          <span class="text-cyan-400 font-bold">•</span>
          <span>${escapeHtml(rec)}</span>
        </li>
      `).join('');
    }

    // 7. Feature Vector Grid
    const feats = data.features || {};
    featureGrid.innerHTML = Object.entries(feats).map(([k, v]) => `
      <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex flex-col">
        <span class="text-slate-500 text-[10px] uppercase truncate" title="${k}">${k}</span>
        <span class="text-white font-bold mt-1 text-xs truncate ${typeof v === 'boolean' && v ? 'text-amber-400' : ''}">${v}</span>
      </div>
    `).join('');

    // Re-render Lucide icons
    if (window.lucide) {
      lucide.createIcons();
    }

    // Reveal results and scroll smoothly
    resultsSection.classList.remove('hidden');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
});

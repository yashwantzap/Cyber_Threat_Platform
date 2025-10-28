// Data and State Management
let vulnerabilities = [];
let trainedModel = null;
const todayDate = new Date().toISOString().slice(0, 10);
document.getElementById('user-date-added').value = todayDate;

// UI Elements
const refreshButton = document.getElementById('refresh-button');
const trainButton = document.getElementById('train-button');
const analyzeUserInputButton = document.getElementById('analyze-user-input');
const statusMessage = document.getElementById('status-message');
const messageText = document.getElementById('message-text');
const loadingSpinner = document.getElementById('loading-spinner');
const vulnerabilitiesList = document.getElementById('vulnerabilities-list');
const analysisSection = document.getElementById('analysis-section');

// User Input Elements
const userCveIdEl = document.getElementById('user-cveid');
const userVulnNameEl = document.getElementById('user-vuln-name');
const userDescriptionEl = document.getElementById('user-description');
const userVendorEl = document.getElementById('user-vendor');
const userProductEl = document.getElementById('user-product');
const userDateAddedEl = document.getElementById('user-date-added');
const userRequiredActionEl = document.getElementById('user-required-action');


// Analysis UI Elements
const cveIdEl = document.getElementById('cve-id');
const riskLevelEl = document.getElementById('risk-level');
const confidenceScoreEl = document.getElementById('confidence-score');
const descriptionEl = document.getElementById('description');
const riskIconEl = document.getElementById('risk-icon');
const mitigationPlanEl = document.getElementById('mitigation-plan');

// --- Core Application Logic ---

/**
 * Communicates with the Flask backend to run a Python script.
 * @param {string} endpoint The API endpoint to call.
 * @param {object} [data={}] Optional JSON payload to send.
 * @returns {Promise<any>} The parsed JSON response from the server.
 */
async function callApi(endpoint, data = {}) {
    try {
        const response = await fetch(`http://localhost:5000/api/${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message);
        }

        return await response.json();
    } catch (e) {
        console.error(`API call to /api/${endpoint} failed:`, e);
        throw e;
    }
}

// --- Dashboard Logic ---

function showMessage(text, type = 'info') {
    messageText.textContent = text;
    statusMessage.classList.remove('hidden', 'bg-red-100', 'bg-green-100', 'bg-yellow-100', 'text-red-800', 'text-green-800', 'text-yellow-800');
    loadingSpinner.classList.add('hidden');
    
    if (type === 'loading') {
        statusMessage.classList.add('bg-yellow-100', 'text-yellow-800');
        loadingSpinner.classList.remove('hidden');
    } else if (type === 'success') {
        statusMessage.classList.add('bg-green-100', 'text-green-800');
    } else if (type === 'error') {
        statusMessage.classList.add('bg-red-100', 'text-red-800');
    } else {
        statusMessage.classList.add('bg-gray-100', 'text-gray-800');
    }
}

async function fetchVulnerabilities() {
    showMessage("Fetching latest vulnerability data...", 'loading');
    try {
        const result = await callApi('collect_data');
        // Note: The data returned here is just the raw stdout from the script.
        // In a real application, the Python script would return JSON data.
        console.log(result.message);
        showMessage("Vulnerabilities collected. Please run 'Train Model' to load them.", 'success');
    } catch (e) {
        showMessage("Failed to fetch data. Please check if the backend server is running.", 'error');
    }
}

async function trainModel() {
    showMessage("Training the machine learning model...", 'loading');
    try {
        const result = await callApi('train_model');
        console.log(result.message);
        showMessage("Model trained and saved successfully! Click on a vulnerability to analyze it.", 'success');
    } catch (e) {
        showMessage("Model training failed. Please check the server console for details.", 'error');
    }
}

async function analyzeVulnerability(vulnerabilityData) {
    analysisSection.classList.add('hidden');
    showMessage(`Analyzing vulnerability ${vulnerabilityData.cveID}...`, 'loading');
    
    try {
        const result = await callApi('analyze_vulnerability', vulnerabilityData);
        
        // The result is the raw output from the Python script.
        // We'll parse it to find the risk level and plan.
        const rawOutput = result.result;
        const predictedRisk = /🎯 Predicted Risk Level: (.*)/.exec(rawOutput)?.[1];
        const confidenceScore = /📊 Confidence Score: (.*)/.exec(rawOutput)?.[1];
        const description = /📝 Description:\s+([\s\S]+?)\s+================================================================================/.exec(rawOutput)?.[1]?.trim();
        const mitigationPlan = /🛡️ MITIGATION PLAN\n={80}\n([\s\S]+?)\n================================================================================/.exec(rawOutput)?.[1]?.trim();

        // Update the analysis section UI
        cveIdEl.textContent = vulnerabilityData.cveID;
        descriptionEl.textContent = description || 'Description not found in output.';
        riskLevelEl.textContent = `Predicted Risk: ${predictedRisk || 'N/A'}`;
        confidenceScoreEl.textContent = confidenceScore || 'N/A';
        mitigationPlanEl.innerHTML = mitigationPlan || 'Mitigation plan not found in output.';

        // Update styling based on risk level
        riskLevelEl.className = 'text-sm font-medium';
        if (predictedRisk === 'High-Risk') {
            riskLevelEl.classList.add('text-red-500');
            riskIconEl.textContent = '🚨';
        } else if (predictedRisk === 'Medium-Risk') {
            riskLevelEl.classList.add('text-yellow-500');
            riskIconEl.textContent = '⚠️';
        } else if (predictedRisk === 'Low-Risk') {
            riskLevelEl.classList.add('text-green-500');
            riskIconEl.textContent = '✅';
        } else {
            riskLevelEl.classList.add('text-gray-500');
            riskIconEl.textContent = '❓';
        }

        analysisSection.classList.remove('hidden');
        showMessage(`Analysis complete for ${vulnerabilityData.cveID}.`, 'success');

    } catch (e) {
        showMessage(`Analysis failed for ${vulnerabilityData.cveID}. Check server console.`, 'error');
    }
}

function renderVulnerabilities() {
    // This function is for a real-world scenario where data_collector returns a JSON payload.
    // Since our backend returns raw text, we'll use hardcoded data for demonstration.
    const vulnerabilities = [
        { cveID: 'CVE-2023-RCE-TEST', vulnerabilityName: 'Apache Struts 2 RCE Vulnerability', vendorProject: 'Apache', product: 'Struts 2' },
        { cveID: 'CVE-2024-SQL-DEMO', vulnerabilityName: 'Example SQL Injection Vulnerability in Web Application', vendorProject: 'ExampleCo', product: 'Web App 3.0' },
        { cveID: 'CVE-2024-LOW-RISK', vulnerabilityName: 'Unauthenticated Stored Cross-Site Scripting (XSS)', vendorProject: 'LowRiskCorp', product: 'SomeApp' }
    ];

    vulnerabilitiesList.innerHTML = '';
    vulnerabilities.forEach(v => {
        const card = document.createElement('div');
        card.className = 'vulnerability-item bg-gray-50 rounded-lg p-6 shadow-md border border-gray-200 hover:border-blue-400';
        card.innerHTML = `
            <h3 class="font-bold text-gray-800 text-lg mb-2">${v.cveID}</h3>
            <p class="text-gray-600 text-sm mb-4 line-clamp-3">${v.vulnerabilityName}</p>
            <p class="text-sm text-gray-400">Vendor: ${v.vendorProject}</p>
            <p class="text-sm text-gray-400">Product: ${v.product}</p>
        `;
        card.onclick = () => analyzeVulnerability(v);
        vulnerabilitiesList.appendChild(card);
    });
}

function handleAnalyzeUserInput() {
    const newVulnerability = {
        cveID: userCveIdEl.value || 'CVE-UNKNOWN',
        vulnerabilityName: userVulnNameEl.value || 'User-Provided Vulnerability',
        shortDescription: userDescriptionEl.value || 'No description provided.',
        vendorProject: userVendorEl.value || 'Unknown',
        product: userProductEl.value || 'Unknown',
        dateAdded: userDateAddedEl.value || todayDate,
        requiredAction: userRequiredActionEl.value || 'User-Provided Action'
    };
    analyzeVulnerability(newVulnerability);
}

// Event Listeners
refreshButton.addEventListener('click', fetchVulnerabilities);
trainButton.addEventListener('click', trainModel);
analyzeUserInputButton.addEventListener('click', handleAnalyzeUserInput);

// Initial load
window.onload = fetchVulnerabilities;

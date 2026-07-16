const dropZone = document.getElementById("dropZone");
const browseButton = document.getElementById("browseButton");
const fileInput = document.getElementById("fileInput");

const selectedFile = document.getElementById("selectedFile");
const selectedFileName = document.getElementById("selectedFileName");
const selectedFileSize = document.getElementById("selectedFileSize");
const removeFileButton = document.getElementById("removeFileButton");

const analyzeButton = document.getElementById("analyzeButton");
const buttonText = document.getElementById("buttonText");
const buttonSpinner = document.getElementById("buttonSpinner");

const statusMessage = document.getElementById("statusMessage");
const resultsSection = document.getElementById("resultsSection");

let currentFile = null;

function formatFileSize(bytes) {
    if (bytes < 1024) {
        return `${bytes} bytes`;
    }

    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }

    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function resetFile() {
    currentFile = null;
    fileInput.value = "";

    selectedFile.classList.add("hidden");
    selectedFileName.textContent = "";
    selectedFileSize.textContent = "";

    analyzeButton.disabled = true;
    statusMessage.textContent = "";
}

function chooseFile(file) {
    if (!file) {
        return;
    }

    if (!file.name.toLowerCase().endsWith(".eml")) {
        resetFile();
        statusMessage.textContent =
            "Unsupported file. Please select an .eml file.";
        return;
    }

    const maximumSize = 10 * 1024 * 1024;

    if (file.size > maximumSize) {
        resetFile();
        statusMessage.textContent =
            "The selected file exceeds the 10 MB limit.";
        return;
    }

    currentFile = file;

    selectedFileName.textContent = file.name;
    selectedFileSize.textContent = formatFileSize(file.size);

    selectedFile.classList.remove("hidden");
    analyzeButton.disabled = false;
    statusMessage.textContent = "";
}

dropZone.addEventListener("click", event => {
    if (event.target === browseButton) {
        return;
    }

    fileInput.click();
});

browseButton.addEventListener("click", event => {
    event.stopPropagation();
    fileInput.click();
});

dropZone.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        fileInput.click();
    }
});

fileInput.addEventListener("change", event => {
    chooseFile(event.target.files[0]);
});

removeFileButton.addEventListener("click", resetFile);

["dragenter", "dragover"].forEach(eventName => {
    dropZone.addEventListener(eventName, event => {
        event.preventDefault();
        dropZone.classList.add("dragging");
    });
});

["dragleave", "drop"].forEach(eventName => {
    dropZone.addEventListener(eventName, event => {
        event.preventDefault();
        dropZone.classList.remove("dragging");
    });
});

dropZone.addEventListener("drop", event => {
    chooseFile(event.dataTransfer.files[0]);
});

function setLoading(isLoading) {
    analyzeButton.disabled = isLoading;

    buttonText.textContent =
        isLoading ? "Analyzing email" : "Run analysis";

    buttonSpinner.classList.toggle("hidden", !isLoading);
}

analyzeButton.addEventListener("click", async () => {
    if (!currentFile) {
        return;
    }

    const formData = new FormData();
    formData.append("file", currentFile);

    setLoading(true);

    statusMessage.textContent =
        "Running header, link and attachment checks.";

    resultsSection.classList.add("hidden");

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            body: formData,
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.detail || "The analysis could not be completed."
            );
        }

        renderResults(data);

        statusMessage.textContent =
            "Analysis completed successfully.";
    } catch (error) {
        statusMessage.textContent = error.message;
    } finally {
        setLoading(false);
    }
});

function renderList(elementId, values, emptyText) {
    const element = document.getElementById(elementId);
    element.innerHTML = "";

    const items = Array.isArray(values) ? values : [];

    if (items.length === 0) {
        const item = document.createElement("li");
        item.textContent = emptyText;
        element.appendChild(item);
        return;
    }

    items.forEach(value => {
        const item = document.createElement("li");
        item.textContent = value;
        element.appendChild(item);
    });
}

function getRiskDescription(level) {
    const descriptions = {
        Low:
            "Few strong phishing indicators were detected. Manual verification is still recommended.",
        Medium:
            "Multiple suspicious characteristics were found. Treat the message with caution.",
        High:
            "Strong phishing indicators were detected. Avoid interacting with the message.",
    };

    return (
        descriptions[level] ||
        "The analysis engine returned an unknown risk classification."
    );
}

function getScoreColor(level) {
    if (level === "High") {
        return "var(--high)";
    }

    if (level === "Medium") {
        return "var(--medium)";
    }

    return "var(--low)";
}

function renderResults(data) {
    const analysis = data.analysis || {};
    const email = data.email || {};

    document.getElementById("resultSubject").textContent =
        email.subject || data.filename || "Email analysis";

    const riskLevel = analysis.risk_level || "Unknown";
    const riskBadge = document.getElementById("riskBadge");

    riskBadge.textContent = `${riskLevel} risk`;
    riskBadge.className = "risk-badge";

    if (["Low", "Medium", "High"].includes(riskLevel)) {
        riskBadge.classList.add(
            `risk-${riskLevel.toLowerCase()}`
        );
    }

    const score = Math.min(
        Number(analysis.risk_score || 0),
        100
    );

    document.getElementById("riskScore").textContent =
        String(score);

    const scoreFill = document.getElementById("scoreFill");
    scoreFill.style.width = `${score}%`;
    scoreFill.style.background = getScoreColor(riskLevel);

    document.getElementById("riskDescription").textContent =
        getRiskDescription(riskLevel);

    const information =
        document.getElementById("emailInformation");

    information.innerHTML = "";

    const rows = [
        ["From", email.from || "Not available"],
        ["To", email.to || "Not available"],
        ["Date", email.date || "Not available"],
        [
            "Attachments",
            String(email.attachments?.length || 0),
        ],
    ];

    rows.forEach(([label, value]) => {
        const row = document.createElement("div");
        row.className = "info-row";

        const labelElement = document.createElement("strong");
        labelElement.textContent = label;

        const valueElement = document.createElement("span");
        valueElement.textContent = value;

        row.appendChild(labelElement);
        row.appendChild(valueElement);

        information.appendChild(row);
    });

    renderList(
        "indicatorList",
        analysis.suspicious_indicators,
        "No strong suspicious indicators were reported."
    );

    renderList(
        "reasonList",
        analysis.reasons,
        "No additional reasoning was provided."
    );

    document.getElementById(
        "recommendedAction"
    ).textContent =
        analysis.recommended_action ||
        "Review the sender and message context before taking action.";

    resultsSection.classList.remove("hidden");

    resultsSection.scrollIntoView({
        behavior: "smooth",
        block: "start",
    });
}
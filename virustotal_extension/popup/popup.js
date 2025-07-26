document.addEventListener("DOMContentLoaded", async () => {
    const apiKeyInput = document.getElementById("apiKey");
    const saveApiKeyButton = document.getElementById("saveApiKey");
    const apiKeyStatus = document.getElementById("apiKeyStatus");
    const currentUrlDisplay = document.getElementById("currentUrl");
    const scanUrlButton = document.getElementById("scanUrl");
    const scanStatus = document.getElementById("scanStatus");
    const messageBox = document.getElementById("messageBox");
    const messageBoxText = document.getElementById("messageBoxText");
    const messageBoxClose = document.getElementById("messageBoxClose");

    let currentTabUrl = "";

    function showMessageBox(message) {
        messageBoxText.textContent = message;
        messageBox.classList.remove("hidden");
    }

    messageBoxClose.addEventListener("click", () => {
        messageBox.classList.add("hidden");
    });

    const storedApiKey = await browser.runtime.sendMessage({ action: "getApiKey" });
    if (storedApiKey) {
        apiKeyInput.value = storedApiKey;
        apiKeyStatus.textContent = "API Key loaded.";
        apiKeyStatus.style.color = "green";
    } else {
        apiKeyStatus.textContent = "No API Key saved. Please enter one.";
        apiKeyStatus.style.color = "orange";
    }

    browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
        currentTabUrl = tabs[0].url;
        currentUrlDisplay.textContent = currentTabUrl;
    }).catch(error => {
        console.error("Error getting current tab URL:", error);
        currentUrlDisplay.textContent = "Could not get current URL.";
    });

    saveApiKeyButton.addEventListener("click", async () => {
        const apiKey = apiKeyInput.value.trim();
        if (apiKey) {
            await browser.storage.local.set({ virustotal_api_key: apiKey });
            apiKeyStatus.textContent = "API Key saved successfully!";
            apiKeyStatus.style.color = "green";
        } else {
            apiKeyStatus.textContent = "API Key cannot be empty.";
            apiKeyStatus.style.color = "red";
        }
    });

    scanUrlButton.addEventListener("click", async () => {
        const apiKey = apiKeyInput.value.trim();
        if (!apiKey) {
            showMessageBox("Please save your VirusTotal API key first.");
            return;
        }

        if (!currentTabUrl) {
            showMessageBox("Could not get the current URL to scan.");
            return;
        }

        scanStatus.textContent = "Scanning...";
        scanStatus.style.color = "blue";
        scanUrlButton.disabled = true;

        try {
			
            await browser.runtime.sendMessage({
                action: "scanUrl",
                url: currentTabUrl,
                apiKey: apiKey
            });
            scanStatus.textContent = "Scan request sent. Check notifications for results.";
            scanStatus.style.color = "green";
        } catch (error) {
            console.error("Error sending scan request:", error);
            scanStatus.textContent = `Error: ${error.message}`;
            scanStatus.style.color = "red";
            showMessageBox(`Failed to send scan request: ${error.message}`);
        } finally {
            scanUrlButton.disabled = false;
        }
    });
});

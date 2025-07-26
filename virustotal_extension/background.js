browser.runtime.onInstalled.addListener(() => {
  browser.contextMenus.create({
    id: "scan-link-with-virustotal",
    title: "Scan Link with VirusTotal",
    contexts: ["link"]
  });
});

browser.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "scan-link-with-virustotal") {
    const linkUrl = info.linkUrl;
    if (linkUrl) {
      const result = await browser.storage.local.get("virustotal_api_key");
      const apiKey = result.virustotal_api_key;

      if (!apiKey) {
        browser.notifications.create({
          type: "basic",
          iconUrl: "icons/vt-48.png",
          title: "VirusTotal Scan Failed",
          message: "Please set your VirusTotal API key in the extension popup."
        });
        return;
      }
      await scanUrlWithVirusTotal(linkUrl, apiKey);
    }
  }
});

browser.runtime.onMessage.addListener(async (message) => {
  if (message.action === "scanUrl") {
    const { url, apiKey } = message;
    if (!apiKey) {
      browser.notifications.create({
        type: "basic",
        iconUrl: "icons/vt-48.png",
        title: "VirusTotal Scan Failed",
        message: "Please set your VirusTotal API key in the extension popup."
      });
      return;
    }
    await scanUrlWithVirusTotal(url, apiKey);
  } else if (message.action === "getApiKey") {

    const result = await browser.storage.local.get("virustotal_api_key");
    return result.virustotal_api_key || "";
  }
});

/**
 * Sends a URL to VirusTotal for scanning and notifies the user of the result.
 * @param {string} url The URL to scan.
 * @param {string} apiKey The VirusTotal API key.
 */
async function scanUrlWithVirusTotal(url, apiKey) {
  const apiUrl = "https://www.virustotal.com/api/v3/urls";

  try {
    const urlId = btoa(url).replace(/\//g, '_').replace(/\+/g, '-').replace(/=+$/, '');
    
    const submitResponse = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `url=${encodeURIComponent(url)}`
    });

    if (!submitResponse.ok) {
      const errorText = await submitResponse.text();
      console.error("VirusTotal URL submission failed:", submitResponse.status, errorText);
      browser.notifications.create({
        type: "basic",
        iconUrl: "icons/vt-48.png",
        title: "VirusTotal Scan Failed",
        message: `Error submitting URL: ${submitResponse.statusText}. Check console for details.`
      });
      return;
    }

    const submitData = await submitResponse.json();
    const analysisId = submitData.data.id;

    const reportUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;
    let reportData;
    let attempts = 0;
    const maxAttempts = 10;
    const delay = 3000;

    browser.notifications.create({
      type: "basic",
      iconUrl: "icons/vt-48.png",
      title: "VirusTotal Scan Initiated",
      message: `Scanning ${url}... Please wait for results.`
    });

    while (attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, delay));
      const reportResponse = await fetch(reportUrl, {
        method: "GET",
        headers: {
          "x-apikey": apiKey
        }
      });

      if (!reportResponse.ok) {
        const errorText = await reportResponse.text();
        console.error("VirusTotal report fetch failed:", reportResponse.status, errorText);
        browser.notifications.create({
          type: "basic",
          iconUrl: "icons/vt-48.png",
          title: "VirusTotal Scan Failed",
          message: `Error fetching report: ${reportResponse.statusText}.`
        });
        return;
      }

      reportData = await reportResponse.json();
      if (reportData.data.attributes.status === "completed") {
        break;
      }
      attempts++;
    }

    if (reportData.data.attributes.status !== "completed") {
      browser.notifications.create({
        type: "basic",
        iconUrl: "icons/vt-48.png",
        title: "VirusTotal Scan Timed Out",
        message: "Analysis did not complete in time. Please check VirusTotal directly."
      });
      return;
    }

    const stats = reportData.data.attributes.stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const undetected = stats.undetected || 0;
    const harmless = stats.harmless || 0;

    const totalDetections = malicious + suspicious;

    let notificationMessage;
    if (totalDetections > 0) {
      notificationMessage = `Malicious: ${malicious}, Suspicious: ${suspicious}. View full report for details.`;
    } else {
      notificationMessage = `No threats detected. Harmless: ${harmless}, Undetected: ${undetected}.`;
    }

    browser.notifications.create({
      type: "basic",
      iconUrl: "icons/vt-48.png",
      title: `VirusTotal Scan Result for ${url}`,
      message: notificationMessage
    });

    const guiReportUrl = `https://www.virustotal.com/gui/url/${urlId}`;
    browser.tabs.create({ url: guiReportUrl });

  } catch (error) {
    console.error("VirusTotal API request failed:", error);
    browser.notifications.create({
      type: "basic",
      iconUrl: "icons/vt-48.png",
      title: "VirusTotal Scan Error",
      message: `An error occurred: ${error.message}. Check console for details.`
    });
  }
}

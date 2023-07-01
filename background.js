// Add a listener to detect when a link is hovered
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
    if (changeInfo.status === "complete" && tab.active) {
      chrome.tabs.executeScript(tabId, { file: "content.js", allFrames: true });
    }
  });
  
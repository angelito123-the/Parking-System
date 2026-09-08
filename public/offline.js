(() => {
  const state = document.getElementById("networkState");
  const retry = document.getElementById("retryButton");
  if (!state || !retry) return;

  const updateState = () => {
    const online = navigator.onLine;
    state.textContent = online ? "Connection restored" : "No connection";
    state.classList.toggle("is-online", online);
    retry.textContent = online ? "Return to app" : "Try again";
  };

  retry.addEventListener("click", () => window.location.reload());
  window.addEventListener("online", updateState);
  window.addEventListener("offline", updateState);
  updateState();
})();

(() => {
    const status = document.getElementById("copy-status");
    for (const button of document.querySelectorAll("[data-copy]")) {
        const value = document.getElementById(button.dataset.copy);
        const icon = button.querySelector("[data-copy-symbol]");
        const check = button.querySelector("[data-copied-symbol]");
        const label = button.textContent;
        let reset;

        function feedback(state, text) {
            button.dataset.copyState = state;
            if (icon) {
                icon.toggleAttribute("hidden", state === "copied");
                check.toggleAttribute("hidden", state !== "copied");
                button.title = text || "Copy token";
            } else {
                button.textContent = text || label;
            }
        }

        button.addEventListener("click", async () => {
            clearTimeout(reset);
            try {
                await navigator.clipboard.writeText(value instanceof HTMLInputElement ? value.value : value.textContent);
                feedback("copied", "Copied");
                status.textContent = icon ? "Edit Token copied." : "Short URL copied.";
            } catch {
                feedback("failed", "Copy failed");
                status.textContent = "Select the text to copy it manually.";
            }
            reset = setTimeout(() => {
                feedback("", "");
                status.textContent = "";
            }, 1600);
        });
    }

    const token = document.getElementById("edit-token");
    const details = document.getElementById("token-details");
    const tokenToggle = document.getElementById("toggle-token");
    const eye = tokenToggle.querySelector("[data-eye-open]");
    const eyeOff = tokenToggle.querySelector("[data-eye-closed]");

    function setTokenVisible(visible) {
        token.type = visible ? "text" : "password";
        const label = visible ? "Hide token" : "Show token";
        tokenToggle.setAttribute("aria-label", label);
        tokenToggle.title = label;
        eye.toggleAttribute("hidden", visible);
        eyeOff.toggleAttribute("hidden", !visible);
    }

    tokenToggle.addEventListener("click", () => setTokenVisible(token.type === "password"));
    details.addEventListener("toggle", () => {
        if (!details.open) setTokenVisible(false);
    });
    window.addEventListener("pagehide", () => {
        setTokenVisible(false);
        details.open = false;
    });

    const qrDetails = document.getElementById("qr-details");
    const qrLabel = document.getElementById("qr-label");
    const container = document.getElementById("qr-container");
    let generated = false;

    qrDetails.addEventListener("toggle", () => {
        const show = qrDetails.open;
        if (show && !generated) {
            new QRCode(container, {
                text: document.getElementById("short-url").href,
                width: 150,
                height: 150,
                correctLevel: QRCode.CorrectLevel.M
            });
            generated = true;
        }
        qrLabel.textContent = show ? "Hide QR" : "Show QR";
    });
})();

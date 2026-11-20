(() => {
    const picker = document.getElementById("expires-at");
    if (!picker || picker.type !== "datetime-local" || !window.FormDataEvent) return;

    const original = picker.getAttribute("value");
    const instant = original ? new Date(original + "Z") : null;
    const pad = (value, width = 2) => String(value).padStart(width, "0");

    function localValue(date) {
        const year = date.getFullYear();
        if (!Number.isFinite(year) || year < 1 || year > 9999) return null;

        const day = [pad(year, 4), pad(date.getMonth() + 1), pad(date.getDate())].join("-");
        const time = [pad(date.getHours()), pad(date.getMinutes())];
        if (date.getSeconds()) time.push(pad(date.getSeconds()));
        return day + "T" + time.join(":");
    }

    const initialLocal = instant ? localValue(instant) : "";
    if (initialLocal !== null) {
        picker.value = initialLocal;
        document.getElementById("expiration-zone").textContent = "local time";
    }
    const initialValue = picker.value;

    function expiration() {
        // Keep the stored instant if the displayed time is unchanged, including repeated DST hours.
        if (instant && picker.value === initialValue) return original + "Z";
        if (!picker.value) return "";
        if (initialLocal === null) return picker.value; // The field is still labeled UTC.

        const date = new Date(picker.value);
        // JavaScript otherwise silently adjusts times that do not exist during a clock change.
        return localValue(date) === picker.value ? date.toISOString() : null;
    }

    function validate() {
        picker.setCustomValidity(expiration() === null ? "Choose a time that exists in your time zone." : "");
    }

    picker.addEventListener("input", validate);
    picker.form.addEventListener("submit", (event) => {
        validate();
        if (!picker.reportValidity()) event.preventDefault();
    });
    picker.form.addEventListener("formdata", (event) => {
        const value = expiration();
        if (value !== null) event.formData.set(picker.name, value);
    });
})();

(function () {
    const storageKey = "conshield.theme";
    const legacyStorageKey = "conshield-theme";
    const cookieName = "conshield.theme";
    const allowedThemes = new Set(["light", "dark"]);

    function getStoredTheme() {
        try {
            const value = window.localStorage.getItem(storageKey) || window.localStorage.getItem(legacyStorageKey);
            return allowedThemes.has(value) ? value : null;
        } catch {
            return null;
        }
    }

    function setStoredTheme(theme) {
        try {
            window.localStorage.setItem(storageKey, theme);
        } catch {
            // Theme choice is cosmetic; ignore storage failures.
        }

        document.cookie = `${cookieName}=${theme}; Path=/; Max-Age=31536000; SameSite=Lax`;
    }

    function applyTheme(theme) {
        const normalized = allowedThemes.has(theme) ? theme : "light";
        document.documentElement.dataset.theme = normalized;
        document.body.dataset.theme = normalized;

        document.querySelectorAll("[data-theme-label]").forEach((label) => {
            label.textContent = normalized === "dark" ? "Тёмная" : "Светлая";
        });

        document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
            button.setAttribute("aria-pressed", normalized === "dark" ? "true" : "false");
        });
    }

    document.addEventListener("DOMContentLoaded", () => {
        applyTheme(getStoredTheme() ?? document.documentElement.dataset.theme ?? "light");

        document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
            button.addEventListener("click", () => {
                const nextTheme = document.body.dataset.theme === "dark" ? "light" : "dark";
                setStoredTheme(nextTheme);
                applyTheme(nextTheme);
            });
        });
    });
})();

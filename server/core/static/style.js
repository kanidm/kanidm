function updateColorScheme() {
    let colorScheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    let invertedColorScheme = colorScheme === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-bs-theme', colorScheme);
    ["bg"].forEach((cls) => {
        Array.from(document.getElementsByClassName(`${cls}-${invertedColorScheme}`)).forEach((e) => {
            if (e.tagName !== "NAV")
                e.classList.replace(`${cls}-${invertedColorScheme}`, `${cls}-${colorScheme}`);
        });
    });
    ["btn", "link", "text"].forEach((cls) => {
        Array.from(document.getElementsByClassName(`${cls}-${colorScheme}`)).forEach((e) => {
            e.classList.replace(`${cls}-${colorScheme}`, `${cls}-${invertedColorScheme}`);
        });
    });
}
updateColorScheme();
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', updateColorScheme);
document.body.addEventListener('htmx:afterOnLoad', updateColorScheme);

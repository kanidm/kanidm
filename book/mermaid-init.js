//* Changes mermaid theme based on selected mdbook theme
const rootElement = document.documentElement;
const darkThemes = ["coal", "navy", "ayu"];
// Get the intersection of the HTML element class list & mdbook's dark themes
const selectedDarkTheme = [...rootElement.classList].filter((c) => darkThemes.includes(c));

if (selectedDarkTheme.length > 0) {
	mermaid.initialize({ startOnLoad: true, theme: "dark" });
} else {
	mermaid.initialize({ startOnLoad: true, theme: "default" });
}


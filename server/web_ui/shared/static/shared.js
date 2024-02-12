// This is easier to have in JS than in WASM
export function modal_hide_by_id(m) {
    const elem = document.getElementById(m);
    const modal = bootstrap.Modal.getInstance(elem);
    modal.hide();
};

export function init_graphviz(m) {
    Viz.instance().then(function(viz) {
        const graphContainer = document.getElementById("graph-container");
        if (graphContainer)
            graphContainer.replaceChildren(viz.renderSVGElement(m))
    });
};

export function open_blank(content) {
    const windowDocument = window.open("", "_blank").document;
    const pre2 = windowDocument.createElement("pre");
    pre2.innerText = content;
    windowDocument.body.appendChild(pre2);
}
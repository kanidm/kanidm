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
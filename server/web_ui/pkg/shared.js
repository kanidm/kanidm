// This is easier to have in JS than in WASM
export function modal_hide_by_id(m) {
    const elem = document.getElementById(m);
    const modal = bootstrap.Modal.getInstance(elem);
    modal.hide();
}

/**
 * Replaces the node with a new node using new_tag, and copies all other attributes from node onto new node
 * @param {Element} node
 * @param {string} new_tag
 * @return the new node
 */
function replace_tag(node, new_tag) {
    const newNode = document.createElement(new_tag);

    [...node.attributes].map(({ name, value }) => {
        newNode.setAttribute(name, value);
    });

    while (node.firstChild) {
        newNode.appendChild(node.firstChild);
    }

    node.parentNode.replaceChild(newNode, node);
    return newNode;
}

/**
 * Loads graphviz and then renders the graph
 * @param {string} graph_src dot language graph source
 */
export function init_graphviz(graph_src) {
    if (typeof Viz !== 'undefined') {
        start_graphviz(graph_src);
    } else {
        let meta = document.querySelector("meta[src='/pkg/external/viz.js']");
        if (meta) {
            let script = replace_tag(meta, "script");
            script.addEventListener('load', () => {
                start_graphviz(graph_src);
            });
        } else {
            console.error("viz.js not found");
        }
    }
}

/**
 * Uses the graphviz library to show a graph
 * @param {string} graph_src dot language graph source
 */
function start_graphviz(graph_src) {
    Viz.instance().then(function(viz) {
        const graphContainer = document.getElementById("graph-container");
        if (graphContainer)
            graphContainer.replaceChildren(viz.renderSVGElement(graph_src))
    });
}

/**
 * Opens a popup window `target=_blank` filled with `content`
 * @param {string} content shown in the pre block
 */
export function open_blank(content) {
    const windowDocument = window.open("", "_blank").document;
    const pre2 = windowDocument.createElement("pre");
    pre2.innerText = content;
    windowDocument.body.appendChild(pre2);
}
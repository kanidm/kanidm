function showPermissionDenied() {
    const permissionDeniedToast = document.getElementById('permissionDeniedToast')
    permissionDeniedToast?.show()
}

function showSaved() {
    const savedToast = document.getElementById('savedToast')
    savedToast?.show()
}

window.onload = function () {
    document.body.addEventListener("permissionDenied", () => { showPermissionDenied() });
    document.body.addEventListener("saved", () => { showSaved() });

}

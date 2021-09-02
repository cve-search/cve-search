$(document).ready(function() {

  initClipboard()

});

function initClipboard(){

    var clipboard = new ClipboardJS('#copy-button');

    clipboard.on('success', function(e) {
        e.clearSelection();
    });

    clipboard.on('error', function(e) {
        console.error('Action:', e.action);
        console.error('Trigger:', e.trigger);
    });
}

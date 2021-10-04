function loadPluginActions(){
  $.getJSON('/plugin/_get_cve_actions',{cve: $("#_cveID").val()},function(data){
    actions = data["actions"]
    $("#cve_actions").empty()
    $("#cve_actions").append('<button class="btn btn-outline-success btn-sm" id="copy-button" data-clipboard-target="#cveInfo"><i class="far fa-clipboard"></i> Copy to Clipboard</button><br />')
    for(var i=0; i < actions.length; i++){
      if(('icon' in actions[i]) || ('text' in actions[i])){
        add="<button id='action-"+i+"'>"
        if('icon' in actions[i]){add+="<i class=" + actions[i]['icon'] + "></i> "}
        if('text' in actions[i]){add+=actions[i]['text']}
        add+="</button><br />"
        $("#cve_actions").append(add);
        if('action' in actions[i]){
          $("#action-"+i).attr('id', "action-"+actions[i]['plugin']+"-"+actions[i]['action'])
          $("#action-"+actions[i]['plugin']+"-"+actions[i]['action']).click(function(e){
            plugin = this.id.split("-")[1]
            act = this.id.split("-")[2]
            $.getJSON('/plugin/'+plugin+'/_cve_action/'+act,{cve: $("#_cveID").val()},function(data){
              parseStatus(data)
              loadPluginActions()
            })
          })
        }
      }
    }
  })
}

$(document).ready(function() {
  loadPluginActions();

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

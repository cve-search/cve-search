function copyToClipboard() {
  var oTable = document.getElementById('cveInfo');
  var rowLength = oTable.rows.length;
  var text = "";
  for (i = 0; i < rowLength; i++){
    var oCells = oTable.rows.item(i).cells;
    var attribute = oCells.item(0).innerHTML;
    var value = oCells.item(1).innerHTML;

    var toAdd = attribute + ": \t" + value;
    text = text + toAdd + "\n";
  }
  text = text.replace("Copy to Clipboard", "");
  text = text.replace(/<\/?[^>]+(>|$)/g, "");
  text = text.replace(/\n\s+\n/g, "\n");
  text = text.trim();
  return text;
}

function loadPluginActions(){
  $.getJSON('/plugin/_get_cve_actions',{cve: $("#_cveID").val()},function(data){
    actions = data["actions"]
    $("#cve_actions").empty()
    $("#cve_actions").append('<button id="copy-button" name="copy"><span class="glyphicon glyphicon-copy" aria-hidden="true"></span> Copy to Clipboard</button><br />')
    for(var i=0; i < actions.length; i++){
      if(('icon' in actions[i]) || ('text' in actions[i])){
        add="<button id='action-"+i+"'>"
        if('icon' in actions[i]){add+="<span class='glyphicon glyphicon-"+actions[i]['icon']+"'></span> "}
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

  var client = new ZeroClipboard($("#copy-button"), {
      moviePath: "/static/js/ZeroClipboard.swf"
    });
  client.setText(copyToClipboard());
});

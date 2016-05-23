function updateDB(){
  setStatus("Database update started", "info")
  $.getJSON('/admin/updatedb', {}, function(data){ parseStatus(data) })
}
function whitelistImport(){ listURLBuilder("/admin/whitelist/import", 'wl');}
function blacklistImport(){ listURLBuilder("/admin/blacklist/import", 'bl');}
function whitelistExport(){ window.location = '/admin/whitelist/export';}
function blacklistExport(){ window.location = '/admin/blacklist/export';}
function dropWhitelist(){
  if(confirm("You are about to drop the whitelist. Are you sure?")){
    $.getJSON('/admin/whitelist/drop', {}, function(data){
      if (parseStatus(data)){$("#wl_rules").text("Whitelist: 0 rules");}
    })
  }
}
function dropBlacklist(){
  if(confirm("You are about to drop the whitelist. Are you sure?")){
    $.getJSON('/admin/blacklist/drop', {}, function(data){
      if (parseStatus(data)){$("#bl_rules").text("Blacklist: 0 rules");}
    })
  }
}
function listURLBuilder(url, list){
  var file = list+"_Import";
  var force = "";
  if ((document.getElementById(file).files).length == 1){
    if (document.getElementById(list+"_ForceImport").checked == true){
      force = "f";
    }else{
      force = "df";
    }
    postURL(url, force, file)
  }else{
    alert('Please select a file');
  }
}
function postURL(url, force, file) {
  var form = document.createElement("FORM");
  form.enctype="multipart/form-data";
  form.method = "POST";
  form.style.display = "none";
  document.body.appendChild(form);
  form.action = url
  inputForce = document.createElement("INPUT");
  inputForce.type = "hidden";
  inputForce.name = "force"
  inputForce.value = force
  form.appendChild(inputForce);
  inputFile = document.getElementById(file);
  form.appendChild(inputFile);
  form.submit();
}

function updateDB(){
  setStatus("Database update started", "info")
  $.getJSON('/admin/updatedb', {}, function(data){ parseStatus(data) })
  .fail(function() { parseStatus({"status": "auth_again"}); })
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
function changePass() {
  var pass1 = document.getElementById("new_pass").value;
  var pass2 = document.getElementById("repeat_pass").value;
  var ok = true;
  if (pass1 != pass2) {
    document.getElementById("new_pass").style.borderColor = "#E34234";
    document.getElementById("repeat_pass").style.borderColor = "#E34234";
  }else {
    data = {'new_pass':pass1, 'current_pass':document.getElementById("current_pass").value}
    $.getJSON('/admin/change_pass', data, function(data){ parseStatus(data) })
    .fail(function() { parseStatus({"status": "auth_again"}); })
  }
}
function requestToken() {
  $.getJSON('/admin/request_token', data, function(data){$("#token").val(data['token'])})
}

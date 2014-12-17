function addCPE(list, item){
  alert("ok")
  var url = "/admin/listmanagement/add/"+list+"/"+btoa(item);
  window.location = url;
}

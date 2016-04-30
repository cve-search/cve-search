function addCPE(list, item){
  $.getJSON('/admin/listmanagement/add', {
    list:list, item:item
  }, function(data) {
    parseStatus(data);
  });
}

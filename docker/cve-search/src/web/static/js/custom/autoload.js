//Autoloads
$(function() {
  $.getJSON('/_get_plugins',{},function(data){
    plugins = data["plugins"]
    if(plugins == undefined || plugins.length == 0){
      $("#sidebar").hide()
      $("body").removeClass("withNav");
    }else{
      $("#plugin-pages").empty()
      for (var i=0; i < plugins.length; i++){
        j=plugins[i];
        $("#plugin-pages").append("<li><a class='expandable' href='/plugin/"+j["link"]+"'> <span class='expanded-element'>"+j["name"]+"</span> </a></li>");
      }
      $("#sidebar").show()
      $("body").addClass("withNav");
    }
  })
})

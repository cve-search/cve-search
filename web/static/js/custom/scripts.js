//Search function
function redirect() {
  var search = document.getElementById("search").value
  if(search == ''){
      var url = "/"; window.location = url;
  } else if(/^CVE-[0-9]{4}-[0-9]{4,6}$/.test(search.toUpperCase())){
    var url = "/cve/" + String(search).toUpperCase(); window.location = url;
  }else{
    var form = document.createElement("form");
    form.method="POST";
    form.action="/search";
    var field = document.createElement("INPUT");
    field.type = "hidden";
    field.name = "search"
    field.value = search
    form.appendChild(field);
    document.body.appendChild(form);
    form.submit();
  }

}

//Bootstrap tooltip
jQuery(function () {
  $("[rel='tooltip']").tooltip();
});

//Back To Top
jQuery(document).ready(function() {
  var offset = 220;
  var duration = 500;
  jQuery(window).scroll(function() {
    if (jQuery(this).scrollTop() > offset) {
      jQuery('.back-to-top').fadeIn(duration);
    } else {
      jQuery('.back-to-top').fadeOut(duration);
    }
  });
  jQuery('.back-to-top').click(function(event) {
    event.preventDefault();
    jQuery('html, body').animate({scrollTop: 0}, duration);
    return false;
  })
});

//Temporary undo class
(function($){
  $.fn.extend({
    removeTemporaryClass: function(className, duration) {
      var elements = this;
      setTimeout(function() {
        elements.addClass(className);
      }, duration);
      return this.each(function() {
        $(this).removeClass(className);
      });
    }
  });
})(jQuery);

$(document).ready(function() {

  $("[id^='colf_']").on('click', function(event){

    $(this).find('i').toggleClass('fa-chevron-circle-down fa-chevron-circle-up');

  });
});

//Search function
function redirect() {
  var url = "/cve/" + document.getElementById("search").value.toUpperCase(); window.location = url;
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

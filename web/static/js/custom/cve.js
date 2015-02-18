jQuery(document).ready(function() {
  jQuery('.colfield').on('click', function (event) {
    if (event.target !== this) return;
    event.preventDefault();
    $(this).toggleClass("semiCollapsed");
  })
});


function oidcLogin() {
    showMessage("OIDC Login", "info")
    $.ajax({
        url: "oidc-login",
        type: "get",
        crossDomain: true,
        success: function(response) {
            window.location.href = response
        },
        error: function(xhr) {
            showMessage("OIDC login", "Some error occured")
        }
      });

}


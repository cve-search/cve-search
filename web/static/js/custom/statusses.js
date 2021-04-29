 function parseStatus(data){
  _ok = false;
  if (data != undefined){

    list = "";
    if (String(data).startsWith('wl_')){
        list = "Whitelist";
    }
    else if (String(data).startsWith('bl_')){
        list = "Blacklist";
    }

    if (typeof data === 'string') {
        status = data
    } else{
        if ('status' in data) {
        status = data["status"]
        }
    }

    switch(status){
      case "logged_in":                 showMessage("Logged in successfully", "success"); _ok=true;break;
      case "auth_again":                showMessage("Please authenticate again", "error"); break;
      case "wrong_user_pass":           showMessage("Combination user / password is wrong", "error"); break;
      case "password_changed":          showMessage("Password updated!", "success"); _ok=true;break;
      case "token_requested":           showMessage("Token successfully changed!", "success"); _ok=true;break;
      case "no_password":               showMessage("Please make sure you enter a password", "error"); break;
      case "outdated_database":         showMessage("The database model is outdated! Please update to the latest database model", "error"); break;
      case "wl_imported":
      case "bl_imported":               showMessage(list+" import finished", "success"); _ok=true;break;
      case "wl_already_filled":
      case "bl_already_filled":         showMessage(list+" is already filled. You can force to drop the database", "info"); break;
      case "wl_dropped":
      case "bl_dropped":                showMessage(list+" dropped", "success"); _ok=true;break;
      case "added_to_list":             showMessage("Rule added to the " + data["listType"], "success"); _ok=true;break;
      case "could_not_add_to_list":     showMessage("Could not add the CPE to the " + data["listType"], "error"); break;
      case "removed_from_list":         showMessage("Rule removed from the " + data["listType"], "success"); _ok=true;break;
      case "already_exists_in_list":    showMessage("This rule or a more global rule already exists in the " + data["listType"], "info"); break;
      case "already_removed_from_list": showMessage("Rule was already removed from the " + data["listType"], "info"); break;
      case "invalid_cpe":               showMessage("This cpe is not valid", "error"); break;
      case "cpelist_updated":           showMessage("The rule was updated", "success"); _ok=true;break;
      case "cpelist_update_failed":     showMessage("Failed to update the rule in the " + data["listType"], "error"); break;
      case "plugin_action_disabled":      showMessage("The plugin is disabled, please restart the webserver", "success"); break;
      case "plugin_action_enabled":      showMessage("The plugin is enabled, please restart the webserver", "success"); break;
      case "plugin_action_complete": _ok=true;break;
    }
  }
  return _ok;
}

function showMessage(message, msg_type){
    const Toast = Swal.mixin({
                            toast: true,
                            position: 'bottom-end',
                            showConfirmButton: false,
                            timer: 3000,
                            timerProgressBar: true,
                            onOpen: (toast) => {
                            toast.addEventListener('mouseenter', Swal.stopTimer)
                            toast.addEventListener('mouseleave', Swal.resumeTimer)
                            }
                        });
                        Toast.fire({
                            icon: msg_type,
                            title: "&nbsp;&nbsp;" + message,
                            })
}

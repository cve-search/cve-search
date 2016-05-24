 function parseStatus(data){
  _ok = false;
  if (data['status'] != undefined){
    list = "";
    if       (data['status'].startsWith('wl_')){ list = "Whitelist";
    }else if (data['status'].startsWith('bl_')){ list = "Blacklist";}

    switch(data['status']){
      case "default":
        if (data['updateOutput'] != undefined){
          setStatus("Last update info <div class='well'><pre>"+data['updateOutput']+"</pre></div>", "success"); break;
        }
        _ok=true;break;
      case "logged_in":                 setStatus("Logged in successfully", "success");                                                               _ok=true;break;
      case "auth_again":                setStatus("Please authenticate again", "danger");                                                                      break;
      case "wrong_user_pass":           setStatus("Combination user / password is wrong", "danger");                                                           break;
      case "password_changed":          setStatus("Password updated!", "success");                                                                    _ok=true;break;
      case "no_password":               setStatus("Please make sure you enter a password", "danger");                                                          break;
      case "outdated_database":         setStatus("The database model is outdated! Please update to the latest database model", "danger");                     break;
      case "db_updated":                setStatus("Database update finished <div class='well'><pre>"+data['updateOutput']+"</pre></div>", "success"); _ok=true;break;
      case "wl_imported":
      case "bl_imported":               setStatus(list+" import finished");                                                                           _ok=true;break;
      case "wl_already_filled":
      case "bl_already_filled":         setStatus(list+" is already filled. You can force to drop the database", "info");                                      break;
      case "wl_dropped":
      case "bl_dropped":                setStatus(list+" dropped", "success");                                                                        _ok=true;break;
      case "added_to_list":             briefShow("Rule added to the "+data["listType"], "success", "ok");                                            _ok=true;break;
      case "could_not_add_to_list":     briefShow("Could not add the CPE to the " +data["listType"], "danger", "remove");                                      break;
      case "removed_from_list":         briefShow("Rule removed from the "+data["listType"], "success", "ok");                                        _ok=true;break;
      case "already_exists_in_list":    briefShow("This rule or a more global rule already exists in the "+data["listType"], "info", "info");                  break;
      case "already_removed_from_list": briefShow("Rule was already removed from the "+data["listType"], "info", "info");                                      break;
      case "invalid_cpe":               briefShow("This cpe is not valid", "danger", "remove");                                                                break;
      case "cpelist_updated":           briefShow("The rule was updated", "success", "ok");                                                           _ok=true;break;
      case "cpelist_update_failed":     briefShow("Failed to update the rule in the "+data["listType"], "danger", "remove");                                   break;
      case "plugin_action_failed":      setStatus("The action of the plugin failed", "danger");                                                                break;
      case "plugin_action_complete":                                                                                                                  _ok=true;break;
      default:
        setStatus("A problem occurred with the server!", "danger");
    }
  }
  return _ok;
}

function setStatus(text, status){
  $("#status-box").empty();
  $("#status-box").removeClass();
  $("#status-box").addClass("alert alert-"+status);
  $("#status-box").append(text);
}

function briefShow(text, status, icon){
  $("#status").removeClass();
  $("#status").addClass("alert alert-"+status);
  $("#status_icon").removeClass();
  $("#status_icon").addClass("glyphicon glyphicon-"+icon+"-sign");
  $("#status_message").empty();
  $("#status_message").append(text);
  $("#status").removeTemporaryClass("hidden", 3000);
}

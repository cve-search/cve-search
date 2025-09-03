function updateDB() {
  showMessage("Starting a database update...", "info")

  let data = {};
  if (document.getElementById("updateCache")?.checked) {
    data.cache = true;
  }

  const checkedInputs = document.querySelectorAll(
    '#updateSources input[type="checkbox"]:checked'
  );
  const checkedSources = Array.from(checkedInputs).map(input => input.value);
  if (checkedSources.length > 0) {
    data.sources = checkedSources;  // array
  }

  $.ajax({
    type: "get",
    url: MountPath + 'admin/updatedb',
    data: data,
    traditional: true,  // serialize array as repeated params
    success: function (response) {
      showMessage(
        "The database is updating in the background. Please allow time for completion.",
        "info"
      );
      parseStatus(response['status'])
    },
    error: function(xhr) {
      let msg = xhr.responseJSON?.message || "An error occurred.";
      if (xhr.status === 409) {
        showMessage(msg, "warning"); // warning on an already running update
      } else {
        showMessage(msg, "error");
        parseStatus("auth_again");
      }
    }
  });

}

function clearLocks() {
  showMessage("Clearing updater locks...", "info");

  $.ajax({
    type: "post",
    url: MountPath + 'admin/clear_updater_locks',
    success: function(response) {
      if (response.removed_locks && response.removed_locks.length > 0) {
        showMessage(
          "Removed updater locks: " + response.removed_locks.join(", "),
          "info"
        );
      } else {
        showMessage("No updater locks were present.", "info");
      }
    },
    error: function(xhr) {
      let msg = xhr.responseJSON?.message || "An error occurred while clearing locks.";
      showMessage(msg, "error");
    }
  });
}

function DisablePlugin(plugin_name) {

  $.ajax({
    type: "get",
    url: MountPath + 'admin/disable/' + plugin_name,
    success: function (response) {
      parseStatus(response['status'])
    },
    error: function (xhr, ajaxOptions, thrownError) {
      showMessage(thrownError, "error")
    }
  });

}

function EnablePlugin(plugin_name) {

  $.ajax({
    type: "get",
    url: MountPath + 'admin/enable/' + plugin_name,
    success: function (response) {
      parseStatus(response['status'])
    },
    error: function (xhr, ajaxOptions, thrownError) {
      showMessage(thrownError, "error")
    }
  });

}

function changePass() {
  var pass1 = document.getElementById("new_pass").value;
  var pass2 = document.getElementById("repeat_pass").value;
  var ok = true;
  if (pass1 != pass2) {
    document.getElementById("new_pass").style.borderColor = "#E34234";
    document.getElementById("repeat_pass").style.borderColor = "#E34234";
  } else {
    data = { 'new_pass': pass1, 'current_pass': document.getElementById("current_pass").value }
    $.ajax({
      type: "post",
      url: MountPath + 'admin/change_pass',
      data: JSON.stringify(data),
      contentType: "application/json; charset=utf-8",
      dataType: "json",
      success: function (response) {
        parseStatus(response['status'])
      },
      error: function (xhr, ajaxOptions, thrownError) {
        showMessage(thrownError, "error")
      }
    });
  }
}

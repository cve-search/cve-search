function updateDB(){
  showMessage("Database update started", "info")

  $.ajax({
        type: "get",
        url: '/admin/updatedb',
        success: function(response) {
            parseStatus(response['status'])
        },
        error: function(xhr, ajaxOptions, thrownError) {
            showMessage(thrownError, "error")
            parseStatus("auth_again")
        }
    });

}

function whitelistImport(){ listURLBuilder("/admin/whitelist/import", 'wl');}
function blacklistImport(){ listURLBuilder("/admin/blacklist/import", 'bl');}
function whitelistExport(){ window.location = '/admin/whitelist/export';}
function blacklistExport(){ window.location = '/admin/blacklist/export';}

function dropWhitelist(){

    const swalWithBootstrapButtons = Swal.mixin({
      customClass: {
        confirmButton: 'btn btn-success btn-sm',
        cancelButton: 'btn btn-danger btn-sm margin-left'
      },
      buttonsStyling: false
    })

    swalWithBootstrapButtons.fire({
      title: 'You are about to drop the Whitelist. Are you sure?',
      text: "You won't be able to revert this!",
      icon: 'warning',
      showCancelButton: true,
      confirmButtonText: 'Yes, drop it!',
    }).then((result) => {
      if (result["value"]) {
        $.ajax({
            type: "get",
            url: '/admin/whitelist/drop',
            success: function(response) {
                parseStatus(response['status'])
                $("#wl_rules").text("Whitelist: 0 rules");
            },
            error: function(xhr, ajaxOptions, thrownError) {
                showMessage(thrownError, "error")
            }
        });
      }
    })
}

function dropBlacklist(){

    const swalWithBootstrapButtons = Swal.mixin({
      customClass: {
        confirmButton: 'btn btn-success btn-sm',
        cancelButton: 'btn btn-danger btn-sm margin-left'
      },
      buttonsStyling: false
    })

    swalWithBootstrapButtons.fire({
      title: 'You are about to drop the Whitelist. Are you sure?',
      text: "You won't be able to revert this!",
      icon: 'warning',
      showCancelButton: true,
      confirmButtonText: 'Yes, drop it!',
    }).then((result) => {
      if (result["value"]) {
        $.ajax({
            type: "get",
            url: '/admin/blacklist/drop',
            success: function(response) {
                parseStatus(response['status'])
                $("#bl_rules").text("Blacklist: 0 rules");
            },
            error: function(xhr, ajaxOptions, thrownError) {
                showMessage(thrownError, "error")
            }
        });
      }
    })
}

function listURLBuilder(url, list){
  var file = list+"_Import";
  var force = "";
  if ((document.getElementById(file).files).length == 1){
    if (document.getElementById(list+"_ForceImport").checked == true){
      force = "f";
    }else{
      force = "df";
    }
    postURL(url, force, file)
  }else{
    alert('Please select a file');
  }
}
function postURL(url, force, file) {
  var form = document.createElement("FORM");
  form.enctype="multipart/form-data";
  form.method = "POST";
  form.style.display = "none";
  document.body.appendChild(form);
  form.action = url
  inputForce = document.createElement("INPUT");
  inputForce.type = "hidden";
  inputForce.name = "force"
  inputForce.value = force
  form.appendChild(inputForce);
  inputFile = document.getElementById(file);
  form.appendChild(inputFile);
  form.submit();
}
function changePass() {
  var pass1 = document.getElementById("new_pass").value;
  var pass2 = document.getElementById("repeat_pass").value;
  var ok = true;
  if (pass1 != pass2) {
    document.getElementById("new_pass").style.borderColor = "#E34234";
    document.getElementById("repeat_pass").style.borderColor = "#E34234";
  } else {
    data = {'new_pass':pass1, 'current_pass':document.getElementById("current_pass").value}
    $.ajax({
        type: "post",
        url: '/admin/change_pass',
        data: JSON.stringify(data),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        success: function(response) {
            parseStatus(response['status'])
        },
        error: function(xhr, ajaxOptions, thrownError) {
            showMessage(thrownError, "error")
        }
    });
  }
}

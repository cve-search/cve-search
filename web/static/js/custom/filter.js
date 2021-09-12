function getFormData(top){

  var form_elements = document.getElementById('filter').elements;

  value_dict = {};

  for (var i = 0; i < form_elements.length; i++) {
    if (form_elements[i].id != "filter_send" && form_elements[i].id != "filter_reset") {
      value_dict[form_elements[i].id] = form_elements[i].value
    }
  }

  $.ajax({
    url: MountPath + "set_filter",
    type: "post",
    data: JSON.stringify(value_dict),
    contentType: "application/json; charset=utf-8",
    dataType: "json",
    success: function(data) {
      check_filter_active();
    },
    error: function(xhr) {
      setFilterError('An error occured while setting the filter. Check the filter parameters.');
      console.log(xhr.statusText + ": " + xhr.responseText);
    },
    complete: function() {
      // Something to do always.
    }
  });
}

function reset_filters() {
  $.ajax({
    url: MountPath + "reset_filter",
    type: "get",
    success: function(response) {
      check_filter_active();
      var table = $('#CVEs').DataTable();
      table.ajax.reload();
    },
    error: function(xhr) {
      setFilterError('An error occured while resetting the filter.');
      console.log(xhr.statusText + ": " + xhr.responseText);
    },
    complete: function() {
      // Something to do always.
    }
  });
}

function check_filter_active() {
  $.ajax({
    url: MountPath + "filter_active",
    type: "get",
    success: function(response) {
      var isTrueSet = (response === true);
      if (isTrueSet) {
        $('#filter_off').addClass('d-none');
        $('#filter_on').removeClass('d-none');
        update_filter_form();
        var table = $('#CVEs').DataTable();
        table.ajax.reload();
      }
      else {
        $('#filter_off').removeClass('d-none');
        $('#filter_on').addClass('d-none')
        $('#filterdiv option').removeClass('active_filter_hilight');
        setFilterError('');
      }
    },
    error: function(xhr) {
      setFilterError('An error occured while getting the filter status.');
      console.log(xhr.statusText + ": " + xhr.responseText);
    },
    complete: function() {
      // Something to do always.
    }
  });
}

function update_filter_form() {
  $.ajax({
    url: MountPath + "get_filter",
    type: "get",
    contentType: "application/json; charset=utf-8",
    dataType: "json",
    success: function(response) {
      // Make active filters selected.
      $('#timeSelect').val(response.timeSelect);
      $('#startDate').val(response.startDate);
      $('#endDate').val(response.endDate);
      $('#timeTypeSelect').val(response.timeTypeSelect);
      $('#cvssVersion').val(response.cvssVersion);
      $('#cvssSelect').val(response.cvssSelect);
      $('#rejectedSelect').val(response.rejectedSelect);
      $('#cvss').val(response.cvss);
      $('#blacklistSelect').val(response.blacklistSelect);
      $('#whitelistSelect').val(response.whitelistSelect);
      $('#unlistedSelect').val(response.unlistedSelect);
      cvssSelectDisable()
      timeSelectDisable()
      // Hilight active select options.
      $('#filterdiv option').removeClass('active_filter_hilight');
      $('#timeSelect option[value=' + response.timeSelect + ']').addClass('active_filter_hilight')
      $('#timeTypeSelect option[value=' + response.timeTypeSelect + ']').addClass('active_filter_hilight')
      $('#cvssVersion option[value=' + response.cvssVersion + ']').addClass('active_filter_hilight')
      $('#cvssSelect option[value=' + response.cvssSelect + ']').addClass('active_filter_hilight')
      $('#rejectedSelect option[value=' + response.rejectedSelect + ']').addClass('active_filter_hilight')
      $('#blacklistSelect option[value=' + response.blacklistSelect + ']').addClass('active_filter_hilight')
      $('#whitelistSelect option[value=' + response.whitelistSelect + ']').addClass('active_filter_hilight')
      $('#unlistedSelect option[value=' + response.unlistedSelect + ']').addClass('active_filter_hilight')
      // Reset any warnings.
      setFilterError('');
    },
    error: function(xhr) {
      setFilterError('An error occured while getting the filter parameters.');
      console.log(xhr.statusText + ": " + xhr.responseText);
    },
    complete: function() {
      // Something to do always.
    }
  });
}

function timeSelectDisable(){
  var selected = document.getElementById("timeSelect").value;
  switch(selected){
    case "all":
      document.getElementById('startDate').readOnly = true;
      document.getElementById('endDate').readOnly = true;
      document.getElementById('timeTypeSelect').readOnly = true;
      break;
    case "from":
      document.getElementById('startDate').readOnly = false;
      document.getElementById('endDate').readOnly = true;
      document.getElementById('timeTypeSelect').readOnly = false;
      break;
    case "until":
      document.getElementById('startDate').readOnly = true;
      document.getElementById('endDate').readOnly = false;
      document.getElementById('timeTypeSelect').readOnly = false;
      break;
    case "between":  // Fallthrough
    case "outside":
      document.getElementById('startDate').readOnly = false;
      document.getElementById('endDate').readOnly = false;
      document.getElementById('timeTypeSelect').readOnly = false;
  }
}

function cvssSelectDisable(){
  var selected = document.getElementById("cvssSelect").value;
  switch(selected){
    case "all":
      document.getElementById('cvss').readOnly = true;
      break;
    default:
      document.getElementById('cvss').readOnly = false;
  }
}

function validateDates(){
  var startDate = new Date(document.getElementById("startDate").value);
  var endDate= new Date(document.getElementById("endDate").value);

  var selected = document.getElementById("timeSelect").value;
  switch(selected){
    case "all":
      break;
    case "from":
      if (!isValidDate(startDate)) {
        setFilterError('Starting date is not set.');
        return false
      }
      break;
    case "until":
      if (!isValidDate(endDate)) {
        setFilterError('End date is not set.');
        return false
      }
      break;
    case "between":  // Fallthrough
    case "outside":
      if (isValidDate(startDate) && isValidDate(endDate)) {
        if (startDate.getTime() > endDate.getTime()) {
          setFilterError('End date before starting date.');
          return false
        }
      } else {
        setFilterError('Both dates must be set.');
        return false
      }
  }
  return true
}

function isValidDate(d) {
  return d instanceof Date && !isNaN(d);
}

function setFilterError(text) {
  $('#filter_warning').text(text);
  if (text != '') {
    $('#filterdiv').collapse("show");
  }
}

function autoClearFilterError() {
  // Reset the filter error if any of the inputs changes.
  $("#filterdiv").on("change", "select", function () {
    setFilterError('')
  });
  $("#filterdiv").on("change", "input[type='date']", function () {
    setFilterError('')
  });
}

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
    case "between":
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

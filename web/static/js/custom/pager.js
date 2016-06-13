// Requires filter.js, where setSetings() is located
function postURL(url) {
  var form = document.getElementById("filter");
  form.action = url;
  form.submit();
}
function next(n){
  setSettings();
  var url = "/r/"+n;
  postURL(url);
}
function previous(n){
  setSettings();
  if(n < 0){
    n = 0;}
  var url = "/r/" + n;
  postURL(url);
}

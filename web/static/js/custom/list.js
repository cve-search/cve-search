function clear(table){
  $("#"+table+"id").val("");
  $("#"+table+"comments").val("");
  $("#"+table+"add").val("Add");
  if(table != "cpe"){$("#"+table+"select").val("targetsoftware");}
  $('#cancel'+table).remove();
  editedcpe="";
  editedkeyword="";
}

var editedcpe;
var editedkeyword;
$(document).ready(function() {
  init();
});

function init(){
  $('#cpes tbody tr').add('#keywords tbody tr').on( 'click', '#edit', function () {
    var table = $(this).closest('table').attr('id').slice(0, -1);
    $("#cancel"+table).remove();
    window["edited"+table] = $(this).closest('tr').find("td").eq(2).text();
    if(table == "cpe"){ var td=3; }else{ var td=4; }
    var comments = $(this).closest('tr').find("td").eq(td).text().split("\n");
    var commentString="";
    for(comment in comments){
      if(comments[comment].trim().length!=0){commentString = commentString + comments[comment].trim() + "\n"};
    }
    commentString = commentString.trim();
    $("#"+table+"id").val(window["edited"+table]);
    $("#"+table+"comments").val(commentString);
    if(table != "cpe"){
      $("#"+table+"select").val($(this).closest('tr').find("td").eq(3).text().trim().replace(" ","").toLowerCase());
    }
    $("#"+table+"add").val("Edit");
    $("#add"+table).append(" <button id='cancel"+table+"' type='button'>Cancel</button> ");
    $('#cancel'+table).click(function() {
      clear(table);
    });
    jQuery('html, body').animate({scrollTop: 0}, 500);
  });
}

function remove(item){

    const swalWithBootstrapButtons = Swal.mixin({
      customClass: {
        confirmButton: 'btn btn-success btn-sm',
        cancelButton: 'btn btn-danger btn-sm margin-left'
      },
      buttonsStyling: false
    })

    swalWithBootstrapButtons.fire({
      title: 'Are you sure you want to remove this rule?',
      text: "You won't be able to revert this!",
      icon: 'warning',
      showCancelButton: true,
      confirmButtonText: 'Yes, remove it!',
    }).then((result) => {
      if (result["value"]) {
        $.getJSON(MountPath + 'admin/removeFromList', {
          list: $("#values").val(), cpe:item
        }, function(data) {
          if(parseStatus(data)){ fillTable(data);}
        });
      }
    })
}

function addItem(cpetype) {
  var CPE, commentArray, keyword;
  var comments = "";
  // get field info and build cpe
  if(cpetype == "cpe"){var listType="cpe"}else{var listType="keyword"}
  CPE = $("#"+listType+"id").val().trim();
  commentArray = $("#"+listType+"comments").val().trim();
  if(cpetype != "cpe"){
    cpetype = $("#keywordselect").val().trim();
  }
  if (commentArray){
    commentArray = commentArray.split("\n");
    for (comment in commentArray){
      comments = comments + "# " + commentArray[comment];
    }
  }
  CPE = CPE+comments;
  // check if cpe was edited
  if(window["edited"+listType]){
    $.getJSON(MountPath + 'admin/editInList', {
      list: $("#values").val(), cpe:CPE, oldCPE:window["edited"+listType], type:cpetype
    }, function(data) {
      if(parseStatus(data)){ fillTable(data);}
    });
  }else{
    //alert($("#values").val());
    $.getJSON(MountPath + 'admin/addToList', {
      list: $("#values").val(), cpe:CPE, type:cpetype
    }, function(data) {
      if(parseStatus(data)){ fillTable(data);}
    });
  }
  clear(listType);
}

function fillTable(data){
  var rules=data['rules'];
  $("#cpes > tbody > tr").remove();
  $("#keywords > tbody > tr").remove();
  var line = "";
  for (i=0;i<rules.length;i++){

    line += "<tr><td><a href='javascript:remove(\""+rules[i]['id']+"\")'><i class='far fa-trash-alt'></i></a></td>";

    line += "<td>"+rules[i]['id']+"</td>";

    if(rules[i]['type']!='cpe'){
      if(rules[i]['type'] == 'targethardware'){        line += "<td>Target Hardware</td>";
      }else if (rules[i]['type'] == 'targetsoftware'){ line += "<td>Target Software</td>";}
    }
    //last td
    line += "<td><ul>";
    if('comments' in rules[i]){
      for (j=0;j<rules[i]['comments'].length;j++){
        line += "<li>"+rules[i]['comments'][j]+"</li>";
      }
    }
    line += "</ul></td></tr>";
    if(rules[i]['type']=='cpe'){ $("#cpes > tbody").append(line);
    }else{                       $("#keywords > tbody").append(line);
    }
    line="";
  }
  init();
}
    

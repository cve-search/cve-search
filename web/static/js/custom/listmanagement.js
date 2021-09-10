function addCPE(list, item){

    data = {"list":list, "item":item}

    $.ajax({
        type: "post",
        url: MountPath + 'admin/listmanagement/add',
        data: JSON.stringify(data),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        success: function(response) {
            parseStatus(response)
        },
        error: function(xhr, ajaxOptions, thrownError) {
            showMessage(thrownError, "error")
        }
    });

}

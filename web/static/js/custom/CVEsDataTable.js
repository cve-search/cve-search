function ConvertDateTime(datetimestring) {
  var date = new Date(datetimestring)
  return date.toISOString().substring(0, 10) + ' - ' + date.toTimeString().substring(0, 5);
}

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function loadCVEsDataTable(pageLength) {
  $('#CVEs').DataTable({
    "processing": true,
    "serverSide": true,
    "ajax": {
      "url": MountPath + "fetch_cve_data",
      "data": function ( d ) {
        d.retrieve = "cves";
      },
      "type": "POST"
    },
    "columnDefs": [
      {"searchable": false, "targets": 0 },
      {bSortable: false, targets: [0, 5]},
    ],
    "order": [[ 6, "desc" ]],
    "orderMulti": false,
    "columns": [
      { "data": "blank",
          render : function(data, type, row) {
            return ''
          }
      },
      { "data": "id",
          render : function(data, type, row) {
            var html = '<a href="' + MountPath + 'cve/'+ row['id'] + '" width="20" height="20" title="Active">'+ row['id'] +'</a>';
            return html
          }
      },
      { "data": "cvss"},
      { "data": "cvss3"},
      { "data": "cvss4"},
      { "data": "summary",
          render : function(data, type, row) {
            return escapeHtml(row['summary'])
          }
      },
      { "data": "lastModified",
          render : function(data, type, row) {
            var dtg = ConvertDateTime(row['lastModified'])
            return dtg
          }
      },
      { "data": "published",
          render : function(data, type, row) {
            var dtg = ConvertDateTime(row['published'])
            return dtg
          }
      },
    ],
    "iDisplayLength": pageLength,
    "language": { 
      "processing": "<img src='" + MountPath + "static/img/ajaxload.gif') }}'> Loading...",
      "zeroRecords": "No records to display", searchPlaceholder: "Regex search...", search: ""
    },
    "search": {
      "regex": true
    }
  });
  $('#CVEs').removeClass('d-none');
}

function loadSearchDataTable(pageLength, freetextsearch, vendor, product) {
  $('#CVEs').DataTable({
    "processing": true,
    "serverSide": false,
    "ajax": {
      "url": MountPath + "fetch_search_data",
      "data": function ( d ) {
        d.search = freetextsearch;
        d.vendor = vendor;
        d.product = product;
      },
      "type": "POST"
    },
    "columnDefs": [
      {"searchable": false, "targets": 0 },
      {bSortable: false, targets: [0, 4]},
    ],
    "order": [[ 5, "desc" ]],
    "orderMulti": false,
    "columns": [
      { "data": "blank",
          render : function(data, type, row) {
            return ''
          }
      },
      { "data": "id",
          render : function(data, type, row) {
            var html = '<a href="' + MountPath + 'cve/'+ row['id'] + '" width="20" height="20" title="Active">'+ row['id'] +'</a>';
            if ('reason' in row) html += '<br /><span class="badge badge-success">' + row['reason'] + '</span>';
            return html
          }
      },
      { "data": "cvss"},
      { "data": "cvss3"},
      { "data": "cvss4"},
      { "data": "summary",
          render : function(data, type, row) {
            return escapeHtml(row['summary'])
          }
      },
      { "data": "lastModified",
          render : function(data, type, row) {
            var dtg = ConvertDateTime(row['lastModified'])
            return dtg
          }
      },
      { "data": "published",
          render : function(data, type, row) {
            var dtg = ConvertDateTime(row['published'])
            return dtg
          }
      },
    ],
    "iDisplayLength": pageLength,
    "language": { 
      "processing": "<img src='" + MountPath + "static/img/ajaxload.gif') }}'> Loading...",
      "zeroRecords": "No records to display", searchPlaceholder: "Regex search...", search: ""
    },
    "search": {
      "regex": true
    }
  });
  $('#CVEs').removeClass('d-none');
}

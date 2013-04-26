function save_options() {
	localStorage["useragent"] = document.getElementById("useragent").value;
	localStorage["referer"] = document.getElementById("referer").value;
	localStorage["adobereader"] = document.getElementById("adobereader").value;
	localStorage["java"] = document.getElementById("java").value;
}

function update_select(item, value) {
  if (!value)
    return;
  var select = document.getElementById(item);
  for (var i = 0; i < select.children.length; i++) {
    var child = select.children[i];
    if (child.value == value) {
      child.selected = "true";
      break;
    }
  }
}

function update_text(item, value) {
	if (!value)
		return;
	document.getElementById(item).value = value;
}

function restore_options() {
  update_select("useragent", localStorage["useragent"]);
  update_text("referer", localStorage["referer"]);
  update_select("adobereader", localStorage["adobereader"]);
  update_select("java", localStorage["java"]);
}

document.addEventListener('DOMContentLoaded', restore_options);
document.querySelector('#save').addEventListener('click', save_options);

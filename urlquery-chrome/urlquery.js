// urlQuery plugin for chrome
// author: earada
// email: earada@alienvault.com

function genericOnClick(info, tab) {
	var http = new XMLHttpRequest();
	url = (typeof(info.linkUrl)!="undefined")?info.linkUrl:info.selectionText;
	console.log("Sent to urlQuery: " + url);
	console.log(info)
	http.open("POST", "http://urlquery.net/api/v2/post.php", true);
	http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	http.onreadystatechange = function() {
		if(http.readyState == 4 && http.status == 200) {
			var obj = JSON.parse(http.responseText);
			if(obj["return_code"] == 3) {
				var tmp = document.createElement("DIV");
				tmp.innerHTML = obj["msg"];
				var msg = tmp.textContent||tmp.innerText;
				alert("UrlQuery "+ msg);
			} else {
				chrome.tabs.create({url: "http://urlquery.net/queued.php?id="+ obj["queue_id"]});
			}
		}
	}
	params = "method=urlquery_submit&url="+encodeURIComponent(url);
	params += "&useragent="+encodeURIComponent(localStorage["useragent"]);
	params += "&referer="+encodeURIComponent(localStorage["referer"]);
	params += "&adobereader="+encodeURIComponent(localStorage["adobereader"]);
	params += "&java="+encodeURIComponent(localStorage["java"]);
	params += "&flags=0";
	http.send(params);
}

var id = chrome.contextMenus.create({"title": "Send to urlQuery",
	"contexts":["link","selection"], "onclick": genericOnClick});

// urlQuery plugin for chrome
// author: earada
// email: earada@alienvault.com

function genericOnClick(info, tab) {
	var http = new XMLHttpRequest();
	console.log("Sent to urlQuery: " + info.linkUrl);
	http.open("POST", "http://urlquery.net/api/v2/post.php", true);
	http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	http.onreadystatechange = function() {
		if(http.readyState == 4 && http.status == 200) {
			var obj = JSON.parse(http.responseText);
			chrome.tabs.create({url: "http://urlquery.net/queued.php?id="+ obj["queue_id"]});
		}
	}
	params = "method=urlquery_submit&url="+encodeURIComponent(info.linkUrl);
	params += "&useragent="+encodeURIComponent(localStorage["useragent"]);
	params += "&referer="+encodeURIComponent(localStorage["referer"]);
	params += "&adobereader="+encodeURIComponent(localStorage["adobereader"]);
	params += "&java="+encodeURIComponent(localStorage["java"]);
	params += "&flags=0";
	http.send(params);
}

var id = chrome.contextMenus.create({"title": "Send to urlQuery",
	"contexts":["link"], "onclick": genericOnClick});

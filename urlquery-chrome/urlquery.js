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
	http.send("method=urlquery_submit&url="+info.linkUrl+"&useragent=Mozilla%2F5.0+(Windows%3B+U%3B+Windows+NT+6.1%3B+en-US%3B+rv%3A1.9.2.13)+Gecko%2F20101203+Firefox%2F3.6.13&referer=&adobereader=8.0&java=1.6.0_26&flags=0");
}

var id = chrome.contextMenus.create({"title": "Send to urlQuery",
	"contexts":["link"], "onclick": genericOnClick});

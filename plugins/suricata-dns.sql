-- suricata-dns
-- type: detector
-- plugin_id: 20000

DELETE FROM plugin WHERE id = "20000";
DELETE FROM plugin_sid where plugin_id = "20000";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (20000, 1, 'suricata-dns', 'Suricata DNS Event');
INSERT IGNORE INTO plugin_sid (plugin_id, sid, name) VALUES (20000, 1, 'suricata-dns: Query');
INSERT IGNORE INTO plugin_sid (plugin_id, sid, name) VALUES (20000, 2, 'suricata-dns: Response');

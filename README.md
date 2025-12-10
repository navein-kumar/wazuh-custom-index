# Wazuh Custom Index Routing Guide

Route specific Wazuh alerts to separate custom indices (e.g., `wazuh-mssql-*`, `wazuh-netstat-*`) instead of default `wazuh-alerts-*` using Filebeat pipeline conditions.

## Overview

| Index Pattern | Purpose |
|---------------|---------|
| `wazuh-alerts-4.x-*` | Default alerts (unchanged) |
| `wazuh-netstat-4.x-*` | Network connection logs |
| `wazuh-mssql-4.x-*` | MSSQL database audit logs |

## Important Notes

- **Existing data NOT affected** - Pipeline changes only affect new incoming logs
- **Multiple custom indices supported** - Add as many as needed
- **Shard consideration** - Each new index creates additional shards (6 per day by default)

---

## Step 1: Update Index Template

### 1.1 Export Current Template

```bash
curl -XGET -k -u admin:<password> "https://<INDEXER_IP>:9200/_template/wazuh?pretty" > /tmp/wazuh-template.json
```

### 1.2 Edit Template

Add your custom index patterns to `index_patterns` array:

```json
"index_patterns": [
  "wazuh-alerts-4.x-*",
  "wazuh-archives-4.x-*",
  "wazuh-netstat-4.x-*",
  "wazuh-mssql-4.x-*"
]
```

### 1.3 Apply Updated Template

```bash
curl -XPUT -k -u admin:<password> "https://<INDEXER_IP>:9200/_template/wazuh" \
  -H 'Content-Type: application/json' -d @/tmp/wazuh-template.json
```

### 1.4 Verify Template

```bash
curl -XGET -k -u admin:<password> "https://<INDEXER_IP>:9200/_template/wazuh?pretty&filter_path=*.index_patterns"
```

---

## Step 2: Modify Filebeat Pipeline

### 2.1 Backup Original Pipeline

```bash
cp /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json \
   /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json.bak
```

### 2.2 Edit Pipeline

File: `/usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json`

Add custom `date_index_name` processors **BEFORE** the default processor.

#### Painless Condition Syntax (Official)

```json
{
  "date_index_name": {
    "if": "ctx?.rule?.groups instanceof List && ctx.rule.groups.contains('YOUR_GROUP')",
    "field": "timestamp",
    "date_rounding": "d",
    "index_name_prefix": "wazuh-YOUR_INDEX-4.x-",
    "index_name_format": "yyyy.MM.dd",
    "ignore_failure": true
  }
}
```

#### Key Syntax Rules

| Syntax | Purpose |
|--------|---------|
| `ctx?.rule?.groups` | Null-safe field access |
| `instanceof List` | Check if groups is array |
| `.contains('group')` | Match group name |
| `ignore_failure: true` | Custom processors |
| `ignore_failure: false` | Default processor only |

#### Default Processor (Must Be Last)

```json
{
  "date_index_name": {
    "if": "!(ctx?.rule?.groups instanceof List && (ctx.rule.groups.contains('netstat') || ctx.rule.groups.contains('mssql')))",
    "field": "timestamp",
    "date_rounding": "d",
    "index_name_prefix": "{{fields.index_prefix}}",
    "index_name_format": "yyyy.MM.dd",
    "ignore_failure": false
  }
}
```

### 2.3 Apply Pipeline Changes

```bash
filebeat setup --pipelines --modules wazuh
systemctl restart filebeat
```

---

## Step 3: Create Decoder & Rules (For Custom Logs)

### 3.1 Create Decoder

File: `/var/ossec/etc/decoders/mssql_decoders.xml`

```xml
<decoder name="mssql-audit">
  <program_name>mssql</program_name>
  <regex>YOUR_REGEX_PATTERN</regex>
  <order>field1,field2</order>
</decoder>
```

### 3.2 Create Rules

File: `/var/ossec/etc/rules/mssql_rules.xml`

```xml
<group name="mssql,database,">
  <rule id="87000" level="3">
    <decoded_as>mssql-audit</decoded_as>
    <description>MSSQL Audit Event</description>
    <group>mssql</group>
  </rule>
</group>
```

> **Important:** The `<group>mssql</group>` tag is what the pipeline condition checks.

### 3.3 Restart Wazuh Manager

```bash
systemctl restart wazuh-manager
```

---

## Step 4: Configure Agent (Optional)

### Windows Event Channel

```xml
<localfile>
  <location>Application</location>
  <log_format>eventchannel</log_format>
  <query>Event[System[Provider[@Name='MSSQLSERVER']]]</query>
</localfile>
```

### File-based Logs

```xml
<localfile>
  <log_format>multi-line-regex</log_format>
  <location>C:\Path\To\MSSQL\Logs\*.sqlaudit</location>
</localfile>
```

---

## Verification Commands

### Check Pipeline Status

```bash
# Via Dev Tools or curl
GET _ingest/pipeline/filebeat-7.10.2-wazuh-alerts-pipeline
```

### Check Template

```bash
GET _template/wazuh
```

### List Custom Indices

```bash
GET _cat/indices/wazuh-netstat-*?v
GET _cat/indices/wazuh-mssql-*?v
GET _cat/indices/wazuh-*?v
```

### Test Filebeat Connection

```bash
filebeat test output
```

### Simulate Pipeline

```bash
POST _ingest/pipeline/filebeat-7.10.2-wazuh-alerts-pipeline/_simulate
{
  "docs": [{
    "_source": {
      "rule": {
        "groups": ["netstat"],
        "id": "100102"
      },
      "timestamp": "2025-12-10T16:53:20.407+0530"
    }
  }]
}
```

---

## Alternative Condition Examples

### By Rule ID

```json
"if": "ctx?.rule?.id == '87000'"
```

### By Decoder Name

```json
"if": "ctx?.decoder?.name == 'mssql-audit'"
```

### By Agent Label

```json
"if": "ctx?.agent?.labels?.group == 'database'"
```

### By Location Field

```json
"if": "ctx?.location != null && ctx.location.contains('mssql')"
```

---

## Adding More Custom Indices

To add another custom index (e.g., firewall logs):

1. **Add to template** `index_patterns`:
   ```json
   "wazuh-firewall-4.x-*"
   ```

2. **Add processor before default**:
   ```json
   {
     "date_index_name": {
       "if": "ctx?.rule?.groups instanceof List && ctx.rule.groups.contains('firewall')",
       "field": "timestamp",
       "date_rounding": "d",
       "index_name_prefix": "wazuh-firewall-4.x-",
       "index_name_format": "yyyy.MM.dd",
       "ignore_failure": true
     }
   }
   ```

3. **Update default processor exclusion**:
   ```json
   "if": "!(ctx?.rule?.groups instanceof List && (ctx.rule.groups.contains('netstat') || ctx.rule.groups.contains('mssql') || ctx.rule.groups.contains('firewall')))"
   ```

4. **Create rules with group tag**:
   ```xml
   <group>firewall</group>
   ```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Logs still in default index | Run `filebeat setup --pipelines --modules wazuh` and restart |
| Pipeline syntax error | Check Painless syntax - use `ctx?.` for null safety |
| Index not created | Verify template includes new pattern |
| No logs appearing | Check `filebeat test output` and Wazuh manager logs |

### Check Filebeat Logs

```bash
tail -f /var/log/filebeat/filebeat
journalctl -u filebeat -f
```

### Check Wazuh Manager Logs

```bash
tail -f /var/ossec/logs/ossec.log
```

---

## Files Reference

| File | Location | Purpose |
|------|----------|---------|
| pipeline.json | `/usr/share/filebeat/module/wazuh/alerts/ingest/` | Route logs conditionally |
| wazuh-template.json | Wazuh Indexer | Index patterns & mappings |
| Custom decoders | `/var/ossec/etc/decoders/` | Parse log format |
| Custom rules | `/var/ossec/etc/rules/` | Alert with group tags |
| Agent config | `/var/ossec/etc/ossec.conf` | Log collection |

---

## References

- [Wazuh Indexer Indices Documentation](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)
- [Wazuh Community - Custom Indices Discussion](https://groups.google.com/g/wazuh/c/ULpb7eSdYO0)
- [Elasticsearch Painless Scripting](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-scripting-painless.html)
- [Filebeat Ingest Pipeline](https://www.elastic.co/guide/en/beats/filebeat/current/configuring-ingest-node.html)

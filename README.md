# qrhelper
An nifty helper class for some common thingys of IBM QRadar.

# Usage:
Provide below params while instancing the class;
- Qradar URL
- Qradar API Token (Authorized Service)
- API Version
- TSL Verification (Default = False)

Exp Usage:
- a = qrhelper('https://192.168.1.1', 'token-xxxx-xxxx-xxxx-xxxxxxxxxxx', '12.0')
- a.close_offense(999, 'Non-Issue')

# List of Functions
  
-    get_offenses: Get the offense list, supports filtering by open ones and max item count.
-    get_offense_details
-    get_offense_notes
-    get_source_addresses: Get SIP addresses from offense
-    get_local_destination_addresses: Get DIP addresses from offense
-    get_rules: Get rules list, supports max item count.
-    get_building_blocks: Get BB names list, supports max item count.
-    get_rule_name: Get rule names by rule is.
-    get_offense_types: Get offense types list.
-    get_offense_type_name: Get offense type name by type id.
-    get_offense_type_property: Get offense type property by type id.
-    get_logsources: Get the log sources list, supports filtering by enabled ones and max item count.
-    get_refset: Get contents of the refset.
-    get_refmap: Get contents of the refmap.
-    get_reftable: Get contents of the reftable.
-    post_refset: Post an item into a refset.
-    post_refmap: Post a key:value pair into a refmap.
-    post_bulkrefmap: Bulk post a list of key:value pairs(json) into a refmap.
-    post_reftable: Post a record with one outer/inner_key and value into a reftable.
-    post_bulkreftable: Bulk post a list records(json) into a reftable.
-    post_offense_note
-    post_aql: Post an AQL query and return search_id.
-    get_aql_results: Get the AQL query result set using a search_id.
-    run_aql: Post an AQL query and get the query result set. (limited with a timeframe, check code and inline comments for modifiying.)
-    close_offense: Close an offense by offense id, supports text based input for offense closing reasons.

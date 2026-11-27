'use strict';
// Every table that is part of a backup. Add new tables here, in db.js, and in the delete-client cleanup in app.js.
// 'backups' (the encrypted backup copies themselves) is deliberately not listed.
module.exports = ['companies', 'users', 'sessions', 'login_history', 'reset_tokens', 'reset_requests', 'tenant_domains', 'customers', 'packages', 'cust_invoices', 'cust_payments', 'expenses', 'voucher_templates', 'voucher_batches', 'vouchers', 'audit_log', 'plans', 'invoices', 'payment_methods', 'payments', 'plan_requests', 'devices', 'device_alerts', 'device_groups', 'router_items', 'router_cmds', 'app_settings', 'deleted_companies'];

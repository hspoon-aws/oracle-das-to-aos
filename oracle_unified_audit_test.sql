audit policy ORA_CIS_RECOMMENDATIONS;
audit policy ORA_ACCOUNT_MGMT;
audit policy ORA_DATABASE_PARAMETER;
audit policy ORA_LOGON_FAILURES;
audit policy ORA_SECURECONFIG;
audit policy ORA_RAS_POLICY_MGMT;
audit policy ORA_RAS_SESSION_MGMT;

create audit policy all_pol_top_level
  actions all
  when q'~ sys_context('userenv', 'session_user') not in ('SYS', 'RDSADMIN', 'RDSSEC', 'AUDSYS') ~'
  evaluate PER STATEMENT
  only toplevel;

AUDIT POLICY all_pol_top_level;

SELECT policy_name FROM audit_unified_enabled_policies;


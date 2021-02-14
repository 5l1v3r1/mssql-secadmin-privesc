# SQL Server - SecurityAdmin Priv Esc

**Advisory**

All the binaries/scripts/code of RunAsUser should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.
* * *

Users what have the `securityadmin` role can escalate their privileges by creating a new user and assigning the `control server` permissions. This script will go through the motions and do it for you. It's my first custom Metasploit module and at some point I hope to build on top of this and have it completely auto pwn the machine.

**Install**

Create the directory structure:
`/home/<user>/.msf4/modules/auxiliary/admin/mssql`

Add the `mssql_secadmin.rb` file to this directory. Then launch metasploit:
```
msfconsole
```
Once loaded, you will need to reload the modules. Inside your Metasploit terminal, run the following command:
```
reload_all
```
Thats it!!

Now if you search for `mssql` you'll see your new module.
```
search mssql
```
![](/search.png)

```
use auxiliary/admin/mssql/mssql_secadmin
```
Once loaded, these will be the settings:

![](/settings.png)

Then once it has run, you should see an output like this **IF** you have the `securityadmin` role.

![](/run.png)

Then simply log in with your new credentials. With the control server permissions you will be allowed to enabled `xp_cmdshell` which you can then use to get execution on the target machine. This is especially useful if the SQL Server service is running as a privilged account.

Hope it helps.

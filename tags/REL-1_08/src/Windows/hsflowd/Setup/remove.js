var loc = new ActiveXObject("WbemScripting.SWbemLocator");
var wmi = loc.ConnectServer(null,"root/CIMv2");

var hsflowd_col = wmi.ExecQuery("SELECT * FROM Win32_Service WHERE Name = 'hsflowd'");
var hsflowd_enum = new Enumerator(hsflowd_col);
var hsflowd = hsflowd_enum.item();
hsflowd.ExecMethod_("StopService");
hsflowd.ExecMethod_("Delete");
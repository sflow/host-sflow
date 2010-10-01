var loc = new ActiveXObject("WbemScripting.SWbemLocator");
var wmi = loc.ConnectServer(null,"root/CIMv2");
var svc = wmi.Get("Win32_Service");
var create = svc.Methods_.Item("Create")
var param = create.InParameters.SpawnInstance_();

param.Name = "hsflowd";
param.DisplayName = "Host sFlow Agent";
param.PathName = Session.Property("CustomActionData");
param.ServiceType = 16; //Own Process
param.StartMode = "Automatic";

out = svc.ExecMethod_(create.Name,param);

var hsflowd_col = wmi.ExecQuery("SELECT * FROM Win32_Service WHERE Name = 'hsflowd'");
var hsflowd_enum = new Enumerator(hsflowd_col);
var hsflowd = hsflowd_enum.item();
out = hsflowd.ExecMethod_("StartService");